package dialer

import (
	"bytes"
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyberok-org/cokmap/internal/probe"
)

type Config struct {
	useAllprobes        bool
	useNullProbe        bool
	saveProductsSummary bool
	rarityLimit         int
	probesLimit         int
	readTimeout         time.Duration
	writeTimeout        time.Duration
	connectTimeout      time.Duration
}
type Worker struct {
	config         Config
	nullProbe      *probe.Probe
	common         []probe.Probe
	golden         []probe.Probe
	tcpCounter     *atomic.Int64
	udpCounter     *atomic.Int64
	targetsCounter *atomic.Int64
}

type ScanData struct {
	probe.Probe
	Response string
	Error    error  `json:"-"`
	ErrorStr string `json:"error,omitempty"`
}

type DialResult struct {
	*Target
	*ScanData
}

func NewConfig(
	useAllprobes, useNullProbe, saveProductsSummary bool,
	rarityLimit, probesLimit int,
	readTimeout, writeTimeout, connectTimeout time.Duration) Config {
	return Config{
		useAllprobes:        useAllprobes,
		useNullProbe:        useNullProbe,
		saveProductsSummary: saveProductsSummary,
		rarityLimit:         rarityLimit,
		probesLimit:         probesLimit,
		readTimeout:         readTimeout,
		writeTimeout:        writeTimeout,
		connectTimeout:      connectTimeout,
	}
}

func NewWorker(cfg Config, common, golden []probe.Probe) *Worker {
	Worker := &Worker{
		config: cfg,
		common: common,
		golden: golden,
	}

	if Worker.config.saveProductsSummary {
		a, b, c := new(atomic.Int64), new(atomic.Int64), new(atomic.Int64)
		Worker.tcpCounter, Worker.udpCounter, Worker.targetsCounter = a, b, c
	}
	if Worker.config.useNullProbe {
		for _, p := range common {
			if p.Name == "NULL" {
				Worker.nullProbe = &p
			}
		}
	}
	return Worker
}

func (w *Worker) ProcessTargets(ctx context.Context, wg *sync.WaitGroup, in <-chan Target, out chan *DialResult) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-in:
			if !ok {
				return
			}

			if w.config.saveProductsSummary {
				w.targetsCounter.Add(1)
			}

			selectedProbes := w.selectProbes(&t)
			result, usedProbes, status := w.scanWithProbes(ctx, &t, selectedProbes)

			if status != ErrConn && status != Success && w.config.useAllprobes {
				blacklist := make(map[string]struct{})
				for _, p := range usedProbes {
					blacklist[p.Name] = struct{}{}
				}
				selectedProbes = w.getAllRemainingProbes(t.Protocol, blacklist)
				result, _, status = w.scanWithProbes(ctx, &t, selectedProbes)
			}

			if status != Success {
				err := Error{target: t, No: status}
				result.Error = err
				result.ErrorStr = err.Error()
				slog.Warn("no data received from all probes", "error", err.Error())
			}

			if w.config.saveProductsSummary {
				if t.Protocol == "tcp" {
					w.tcpCounter.Add(1)
				} else {
					w.udpCounter.Add(1)
				}
			}

			out <- &DialResult{
				&t,
				result,
			}
		}
	}
}

var httpProbes = map[string]struct{}{
	"GetRequest":        {},
	"HTTPOptions":       {},
	"FourOhFourRequest": {},
}

var newLine = []byte{0x0d, 0x0a}

func modifyHTTPProbe(data []byte, target *Target) []byte {

	idxEndHeaders := bytes.Index(data, newLine) // find first "\r\n"
	if idxEndHeaders == -1 {
		return data
	}

	hostHeader := []byte("\r\nHost: " + target.IP)

	modified := make([]byte, 0, len(data)+len(hostHeader))
	modified = append(modified, data[:idxEndHeaders]...)
	modified = append(modified, hostHeader...)
	modified = append(modified, data[idxEndHeaders:]...)

	return modified
}

func (w *Worker) scanWithProbes(ctx context.Context, target *Target, probes []probe.Probe) (result *ScanData, usedProbes []probe.Probe, status Errno) {
	result = new(ScanData)
	for _, p := range probes {
		var response []byte

		probeToSend := probe.DecodeData(p.Data)
		if _, ok := httpProbes[p.Name]; ok {
			probeToSend = modifyHTTPProbe(probeToSend, target)
		}

		slog.Debug("send probe", "data", string(probeToSend))
		response, status = w.grabResponse(ctx, target, probeToSend)
		switch status {
		case Success:
		case ErrConn:
			slog.Debug("connection refused", "target", target.GetAddress(), "err", status.String(), "probe", p.Name)
			return result, probes, status
		default:
			slog.Debug("failed try to grab response", "target", target.GetAddress(), "err", status.String(), "probe", p.Name)
			continue
		}

		slog.Debug("got response ", "target", target.GetAddress(), "len", strconv.Itoa(len(response)), "probe name", p.Name)
		result.Response = string(response)
		result.Probe = p
		return result, probes, status
	}
	return result, probes, status
}

func (w *Worker) grabResponse(ctx context.Context, t *Target, data []byte) ([]byte, Errno) {
	tls := t.Protocol != "udp" && t.SecureUse
	switch {
	case tls:
		dialer := net.Dialer{Timeout: w.config.readTimeout}
		response := []byte{}
		errno := w.tlsDial(ctx, *t, data, &dialer, &response)
		return response, errno
	default:
		return w.defaultDial(ctx, t, data)
	}
}

// default dial send udp and tcp packet and reads packets from connected socket if its TCP end at io.EOF
// UDP receive all packets while deadline duration which can help to determine products
func (w *Worker) defaultDial(ctx context.Context, t *Target, data []byte) ([]byte, Errno) {
	response := []byte{}
	dialer := net.Dialer{Timeout: w.config.connectTimeout}
	conn, err := dialer.DialContext(ctx, t.Protocol, t.GetAddress())
	errno := classifyNetworkError(err)
	if errno != 0 {
		slog.Warn("dial", t.Protocol, err, "target", t.GetAddress())
		return []byte{}, errno
	}

	w.receivePackets(conn, data, &response, &errno)
	conn.Close()
	if t.Protocol != "udp" {
		tlserr := w.tlsDial(ctx, *t, data, &dialer, &response)
		if tlserr == Success {
			t.SecureUse = true
			errno = Success
		}
	}

	return response, errno
}

func (w *Worker) tlsDial(ctx context.Context, t Target, data []byte, dialer *net.Dialer, response *[]byte) Errno {
	tlsDialer := tls.Dialer{NetDialer: dialer, Config: &tls.Config{InsecureSkipVerify: true}}
	conn, err := tlsDialer.DialContext(ctx, t.Protocol, t.GetAddress())
	errno := classifyNetworkError(err)
	if errno != 0 {
		slog.Warn("dial tls", "error", err, "target", t.GetAddress())
		return errno
	}
	defer conn.Close()
	w.receivePackets(conn, data, response, &errno)

	return errno
}

func (w *Worker) receivePackets(conn net.Conn, data []byte, response *[]byte, errno *Errno) {
	if len(data) > 0 {
		conn.SetWriteDeadline(time.Now().Add(w.config.writeTimeout))
		_, err := conn.Write(data)
		if err != nil {
			slog.Warn("write", "error", err, "target", conn.RemoteAddr().String())
			*errno = ErrWrite
			return
		}
	}
	conn.SetReadDeadline(time.Now().Add(w.config.readTimeout))
	for {
		buff := make([]byte, 1024)
		msgPartLen, err := conn.Read(buff)
		if err != nil {
			*errno = classifyReadError(err, len(*response))
			if *errno != Success {
				slog.Warn("read", "error", err, "target", conn.RemoteAddr().String())
			}
			break
		}
		if msgPartLen > 0 {
			*response = append(*response, buff[:msgPartLen]...)
		}
	}
}

func (w *Worker) GetTargetsSummaryCounters() (total, tcp, udp int64) {
	return w.targetsCounter.Load(), w.tcpCounter.Load(), w.udpCounter.Load()
}
