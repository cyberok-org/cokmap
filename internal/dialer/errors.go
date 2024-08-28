package dialer

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

type Error struct {
	target Target
	No     Errno `json:"-"`
}

type Errno uint8

const (
	Success          Errno = 0
	ErrConn          Errno = 1
	ErrRead          Errno = 2
	Timeout          Errno = 3
	_                Errno = 4
	ErrWrite         Errno = 5
	EmptyResponse    Errno = 6
	ErrTLS           Errno = 7
	ErrConnUndefined Errno = 8
	ErrConnClosed    Errno = 9
	ErrReadTimeout   Errno = 10
	ErrReadUndefined Errno = 11
)

var cokmaperrors = map[Errno]string{
	0x0:              "",
	ErrConn:          "target actively refused connection",
	ErrRead:          "response is empty from active connection",
	Timeout:          "received connection timeout",
	ErrWrite:         "write error",
	EmptyResponse:    "empty response",
	ErrTLS:           "TLS handshake error",
	ErrConnUndefined: "undefined connection error",
	ErrReadUndefined: "undefined read error",
	ErrConnClosed:    "remote conn closed while waiting response",
	ErrReadTimeout:   "no packets received read timeout",
}

func (e Errno) String() string {

	if err, ok := cokmaperrors[e]; ok {
		return err
	}
	return "undefined error"
}

func (v Error) Error() string {
	return v.No.String()
}

func (v Error) ErrorTarget() string {
	return fmt.Sprintf("%s target: %s", v.No.String(), v.target.GetAddress())
}

func classifyNetworkError(err error) Errno {
	if err == nil {
		return 0
	}

	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) {
		return ErrConn
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Timeout
	}

	var tlsErr tls.RecordHeaderError
	if errors.As(err, &tlsErr) {
		return ErrTLS
	}

	return ErrConnUndefined
}

func classifyReadError(err error, respLen int) Errno {
	if err != nil && respLen > 0 {
		return 0
	}
	switch {
	case err == io.EOF && respLen == 0:
		return EmptyResponse
	case errors.Is(err, syscall.ECONNRESET):
		return ErrConnClosed
	case errors.Is(err, os.ErrDeadlineExceeded):
		return ErrReadTimeout
	}

	return ErrReadUndefined
}
