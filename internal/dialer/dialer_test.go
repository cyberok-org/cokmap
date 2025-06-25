package dialer

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyberok-org/cokmap/internal/probe"

	"github.com/stretchr/testify/require"
)

type UDPServer struct {
	ip   string
	port string
}

func (s *UDPServer) StartServe() {

}

type handler struct {
	msg string
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, h.msg)
}

func TestSelectProbes(t *testing.T) {
	type testCase struct {
		w             *Worker
		expectedCount int
	}
	testCases := []testCase{
		{
			w: &Worker{config: Config{
				probesLimit: 1,
				rarityLimit: 2,
			},
				common: []probe.Probe{
					{
						Rarity:         1,
						TransportProto: "tcp",
					},
					{
						Rarity:         2,
						Ports:          "143",
						TransportProto: "tcp",
					},
				},
			},
			expectedCount: 2,
		},
		{
			w: &Worker{config: Config{
				probesLimit: 4,
				rarityLimit: 1,
			},
				common: []probe.Probe{
					{
						Rarity:         1,
						TransportProto: "udp",
					},
					{
						Rarity:         1,
						TransportProto: "tcp",
					},
					{
						Rarity:         2,
						TransportProto: "tcp",
					},
					{
						Rarity:         3,
						TransportProto: "udp",
					},
				},
			},
			expectedCount: 1,
		},
		{
			w: &Worker{
				config: Config{
					probesLimit: 1,
					rarityLimit: 3,
				},
				common: []probe.Probe{
					{
						Rarity:         1,
						TransportProto: "tcp",
					},
					{
						Rarity:         3,
						TransportProto: "tcp",
					},
					{
						Rarity:         4,
						TransportProto: "tcp",
					},
				},
				golden: []probe.Probe{
					{
						Rarity:         2,
						Golden:         true,
						TransportProto: "tcp",
					},
					{
						Rarity:         5,
						Golden:         true,
						TransportProto: "tcp",
					},
				},
			},
			expectedCount: 2,
		},
	}
	target := Target{Port: 143, Protocol: "tcp"}

	for i, tc := range testCases {
		ps := tc.w.selectProbes(&target)
		if len(ps) != tc.expectedCount {
			t.Errorf("caseid %d len(ps) %d != expectedCount %d ", i, len(ps), tc.expectedCount)
		}
		for _, p := range ps {
			if p.TransportProto != target.Protocol {
				t.Fail()
			}
		}
	}
}

func TestBlackListProbes(t *testing.T) {
	type testCase struct {
		w         *Worker
		blackList map[string]struct{}
		expected  int
	}
	tc := []testCase{
		{
			w: &Worker{
				common: []probe.Probe{
					{
						Name:           "GET",
						TransportProto: "tcp",
					},
					{
						Name:           "KDA",
						TransportProto: "tcp",
					},
					{
						Name:           "kk",
						TransportProto: "udp",
					},
					{
						Name:           "qwf",
						TransportProto: "udp",
					},
				},
				config: Config{
					useAllprobes: true,
				},
			},
			expected: 2,
		},
		{
			w: &Worker{
				common: []probe.Probe{
					{
						Name:           "GET",
						TransportProto: "tcp",
					},
					{
						Name:           "KDA",
						TransportProto: "tcp",
					},
				},
				config: Config{
					useAllprobes: true,
				},
			},
			blackList: map[string]struct{}{
				"GET": {},
				"KDA": {},
			},
			expected: 0,
		},
	}
	for _, c := range tc {
		probes := c.w.getAllRemainingProbes("tcp", c.blackList)
		if len(probes) != c.expected {
			t.Errorf("len after exclude blacklist should be: %d actual: %d", c.expected, len(probes))
		}
	}
}
func TestGrabResponse(t *testing.T) {
	target := Target{Protocol: "tcp", IP: "127.0.0.1", Port: 8085}
	listener, err := net.Listen("tcp", "127.0.0.1:8085")
	if err != nil {
		fmt.Println(err)
		return
	}
	listMsg := []byte{0x1}
	sendMsg := []byte{0x0, 0x0}
	go func(listener net.Listener) {
		defer listener.Close()
		conn, _ := listener.Accept()
		defer conn.Close()
		n, _ := conn.Read(make([]byte, 1024))
		require.Equal(t, len(sendMsg), n)
		conn.Write(listMsg)
	}(listener)
	// v := New(context.Background(), &Config{readTimeout: 5 * time.Second, sendTimeout: 5 * time.Second})
	w := NewWorker(Config{}, nil, nil)
	w.config.readTimeout = 5 * time.Second
	w.config.writeTimeout = 5 * time.Second
	w.config.connectTimeout = 5 * time.Second
	response, errno := w.grabResponse(context.Background(), &target, sendMsg)
	require.Equal(t, Errno(0x0), errno)

	require.Equal(t, listMsg, response)
}

func TestGrabResponseUDP(t *testing.T) {
	target := Target{Protocol: "udp", IP: "127.0.0.1", Port: 8085}

	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8085")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	sendMsg := []byte{0x0, 0x0}
	listMsg := []byte{0x1}

	done := make(chan struct{})
	go func() {
		defer close(done)
		data := make([]byte, 1024)
		n, remoteAddr, err := listener.ReadFromUDP(data)
		if err != nil {
			t.Errorf("Error reading from UDP socket: %v", err)
			return
		}
		require.Equal(t, len(sendMsg), n)
		_, err = listener.WriteToUDP(listMsg, remoteAddr)
		if err != nil {
			t.Errorf("Error sending response: %v", err)
		}
	}()

	w := NewWorker(Config{}, nil, nil)

	w.config.readTimeout = 5 * time.Second
	w.config.writeTimeout = 5 * time.Second
	w.config.connectTimeout = 5 * time.Second

	response, errno := w.grabResponse(context.Background(), &target, sendMsg)

	<-done

	require.Equal(t, Errno(0x0), errno)
	require.Equal(t, listMsg, response)
}
func TestGrabTLSResponse(t *testing.T) {
	servResp := "nginx"
	// Extract the host and port from the server URL
	// Configure cokmap with reasonable timeouts
	w := NewWorker(Config{}, nil, nil)

	w.config.readTimeout = 5 * time.Second
	w.config.writeTimeout = 5 * time.Second
	w.config.connectTimeout = 5 * time.Second

	h := &handler{msg: servResp}
	s := httptest.NewUnstartedServer(h)
	s.StartTLS()
	rawIp := strings.Trim(s.URL, "https://")
	response, errno := w.grabResponse(context.Background(), &Target{
		Protocol: "tcp",
		IP:       rawIp,
	}, []byte("GET / HTTP/1.0\r\n\r\n"))
	require.Equal(t, errno, Errno(0x0))
	require.Equal(t, true, strings.Contains(string(response), servResp))
}

func TestCheckTLSFlag(t *testing.T) {
	w := NewWorker(Config{}, nil, nil)

	w.config.readTimeout = 5 * time.Second
	w.config.writeTimeout = 5 * time.Second
	w.config.connectTimeout = 5 * time.Second

	h := &handler{}
	s := httptest.NewUnstartedServer(h)
	s.StartTLS()
	rawIp := strings.Trim(s.URL, "https://")
	target := &Target{
		Protocol: "tcp",
		IP:       rawIp,
	}
	w.grabResponse(context.Background(), target, []byte("GET / HTTP/1.0\r\n\r\n"))
	if !target.SecureUse {
		require.Fail(t, "target should be TLS")
	}
}

func TestGraTLSResponse(t *testing.T) {
	servResp := "nginx"
	// Extract the host and port from the server URL
	// Configure cokmap with reasonable timeouts
	w := NewWorker(Config{}, nil, nil)

	w.config.readTimeout = 5 * time.Second
	w.config.writeTimeout = 5 * time.Second
	w.config.connectTimeout = 5 * time.Second

	h := &handler{msg: servResp}
	s := httptest.NewUnstartedServer(h)
	s.StartTLS()
	rawIp := strings.Trim(s.URL, "https://")
	response, errno := w.grabResponse(context.Background(), &Target{
		Protocol: "tcp",
		IP:       rawIp,
	}, []byte("GET / HTTP/1.0\r\n\r\n"))
	require.Equal(t, Errno(0x0), errno)
	require.Equal(t, true, strings.Contains(string(response), servResp))
}

func TestEmptygrabResponse(t *testing.T) {
	target := Target{Protocol: "tcp", IP: "127.0.0.1", Port: 8087}
	w := NewWorker(Config{}, nil, nil)

	w.config.readTimeout = 5 * time.Second
	w.config.writeTimeout = 5 * time.Second
	w.config.connectTimeout = 5 * time.Second

	_, errno := w.grabResponse(context.Background(), &target, []byte{})
	require.NotEqual(t, Errno(0x0), errno)
}

func TestScanWithProbes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:8087")
	if err != nil {
		fmt.Println(err)
		return
	}
	listMsg := []byte{0x1}
	sendMsg := []byte{0x0, 0x5}
	go func(listener net.Listener) {
		defer listener.Close()
		for {
			conn, _ := listener.Accept()
			buf := make([]byte, 5)
			n, _ := conn.Read(buf)
			if bytes.Equal(sendMsg, buf[:n]) {
				conn.Write(listMsg)
				break
			}
		}
	}(listener)

	target := Target{Protocol: "tcp", IP: "127.0.0.1", Port: 8087}
	probes := []probe.Probe{
		{TransportProto: "tcp", Name: "NULL", Data: "qwfqwf"},
		{TransportProto: "tcp", Name: "GET", Data: string(sendMsg)},
	}
	w := NewWorker(Config{}, nil, nil)

	w.config.readTimeout = 5 * time.Second
	w.config.writeTimeout = 5 * time.Second
	w.config.connectTimeout = 5 * time.Second

	res, _, errno := w.scanWithProbes(context.Background(), &target, probes)
	require.Equal(t, Errno(0x0), errno)
	require.Equal(t, listMsg, []byte(res.Response))
	require.Equal(t, probes[1].Name, res.Probe.Name)
}

func TestScanWithRemainingProbes(t *testing.T) {
	listMsg := []byte{0x1}
	sendMsg := []byte{0x0, 0x5}
	sendMsg2 := []byte{0x01, 0x02}
	serverStarted := make(chan struct{})

	handle := func(conn net.Conn) {
		for {
			buf := make([]byte, 5)
			n, _ := conn.Read(buf)
			if bytes.Equal(sendMsg2, buf[:n:n]) {
				conn.Write(listMsg)
			}
		}
	}

	go func() {
		listener, _ := net.Listen("tcp", "127.0.0.1:8087")
		defer listener.Close()
		serverStarted <- struct{}{}
		for {
			conn, _ := listener.Accept()
			go handle(conn)
		}
	}()

	<-serverStarted

	target := Target{Protocol: "tcp", IP: "127.0.0.1", Port: 8087}
	expectedProbeName := "Expected"
	probes := []probe.Probe{
		{TransportProto: "tcp", Name: "NULL", Data: string(sendMsg)},
		{TransportProto: "tcp", Name: "GET", Data: string(sendMsg)},
		{TransportProto: "tcp", Name: "qfw", Data: string(sendMsg)},
		{TransportProto: "tcp", Name: expectedProbeName, Data: string(sendMsg2)},
	}

	w := NewWorker(Config{
		useAllprobes: true,
		rarityLimit:  2,
		probesLimit:  2,
	}, probes, nil)

	w.config.readTimeout = 2 * time.Second
	w.config.writeTimeout = 2 * time.Second
	w.config.connectTimeout = 2 * time.Second

	in := make(chan Target)
	out := make(chan *DialResult)
	go w.ProcessTargets(context.Background(), &sync.WaitGroup{}, in, out)
	in <- target
	res := <-out
	require.Equal(t, "", res.ErrorStr)
	require.Equal(t, listMsg, []byte(res.Response))
	require.Equal(t, expectedProbeName, res.Probe.Name)
}
