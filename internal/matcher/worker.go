package matcher

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"sync"

	"github.com/cyberok-org/cokmap/internal/dialer"
	"github.com/cyberok-org/cokmap/internal/probe"
)

type Worker struct {
	summary            *ExtractSummary
	extractProducts    func(matchers []byte, banner []rune, socket string) ([]byte, error)
	expressionsByProbe map[string][]byte
	probesByName       map[string]probe.Probe
}
type ExtractResult struct {
	*dialer.DialResult
	Products []HostInfo
}

type HostInfo struct {
	Probe       string `json:"probe"`
	Service     string `json:"service"`
	Regex       string `json:"regex"`
	FaviconHash string `json:"favicon_hash,omitempty"`
	SoftMatch   bool   `json:"softmatch"`
	Error       string `json:"error,omitempty"`
	Info[string]
}

type Info[T any] struct {
	VendorProductName T   `json:"vendorproductname,omitempty"`
	Version           T   `json:"version,omitempty"`
	Info              T   `json:"info,omitempty"`
	Hostname          T   `json:"hostname,omitempty"`
	OS                T   `json:"os,omitempty"`
	DeviceType        T   `json:"devicetype,omitempty"`
	CPE               []T `json:"cpe,omitempty"`
}

func NewWorker(createSummary, probesSummary, errorsSummary bool,
	expressionsByProbe map[string][]byte, probesByName map[string]probe.Probe,
	extractProducts func(matchers []byte, banner []rune, socket string) ([]byte, error)) *Worker {
	w := &Worker{expressionsByProbe: expressionsByProbe, probesByName: probesByName, extractProducts: extractProducts}
	if createSummary {
		w.summary = new(ExtractSummary)
		w.summary.logErrs = errorsSummary
		w.summary.logProbes = probesSummary
		w.summary.services, w.summary.products, w.summary.probes = sync.Map{}, sync.Map{}, sync.Map{}
	}

	return w
}

func (w *Worker) ProcessBanners(ctx context.Context, wg *sync.WaitGroup, in chan *dialer.DialResult, out chan *ExtractResult) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case grab, ok := <-in:
			if !ok {
				return
			}
			filtered := w.getMatchersByProbe(grab.Probe.Name, grab.Target)
			var r []rune
			var err error
			if grab.Probe.HexFormat {
				r, err = hexStringToRunes(hex.EncodeToString([]byte(grab.Response)))
				if err != nil {
					r = []rune(grab.Response)
					slog.Warn("got error from parsing response", "target", grab.IP, "error", err.Error())
				}
			} else {
				r = []rune(grab.Response)
			}
			extractedData, err := w.extractProducts(filtered, r, grab.IP)
			if err != nil {
				grab.ErrorStr = err.Error()
			}
			hostInfo := []HostInfo{}
			err = json.Unmarshal(extractedData, &hostInfo)
			if err != nil {
				slog.Warn("got error from unmarshaling result from extract func", "target", grab.IP, "error", err.Error())
				continue
			}
			w.saveProductsSummary(grab, hostInfo)

			out <- &ExtractResult{
				grab,
				hostInfo,
			}
		}
	}
}

func (w *Worker) getMatchersByProbe(probeName string, target *dialer.Target) []byte {
	var filtered []byte
	p, ok := w.expressionsByProbe[probeName]
	if !ok {
		for k, pack := range w.expressionsByProbe {
			probeData, ok := w.probesByName[k]
			if !ok || probeData.TransportProto != target.Protocol || !probeData.ContainsPort(target.Port) {
				continue
			}
			filtered = append(filtered, pack...)
		}
	} else {
		filtered = append(filtered, p...)
	}

	return filtered
}
