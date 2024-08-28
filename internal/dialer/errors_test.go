package dialer

import (
	"crypto/tls"
	"errors"
	"syscall"
	"testing"
)

func TestClassifyNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected Errno
	}{
		{"Nil error", nil, 0},
		{"Connection refused", syscall.ECONNREFUSED, ErrConn},
		{"Host unreachable", syscall.EHOSTUNREACH, ErrConn},
		{"Timeout error", netTimeoutError{}, Timeout},
		{"TLS record header error", tls.RecordHeaderError{}, ErrTLS},
		{"Unknown error", errors.New("unknown error"), ErrConnUndefined},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := classifyNetworkError(tc.err)
			if result != tc.expected {
				t.Errorf("Expected %v, but got %v", tc.expected, result)
			}
		})
	}
}

type netTimeoutError struct{}

func (e netTimeoutError) Error() string   { return "timeout error" }
func (e netTimeoutError) Timeout() bool   { return true }
func (e netTimeoutError) Temporary() bool { return false }
