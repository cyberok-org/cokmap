package matcher

import (
	"cokmap/internal/dialer"
	"cokmap/internal/probe"
	"testing"
)

func TestGetMatchersByName(t *testing.T) {
	type testCase struct {
		probeName string
		w         *Worker
		expected  int
	}
	testCases := []testCase{
		{ // just want to get  {{}, {}} this empty structs
			probeName: "NULL",
			w:         &Worker{expressionsByProbe: map[string][]byte{"NULL": []byte{0x02}}},
			expected:  1,
		},
		{ // want to get all matchers
			probeName: "qwfqwf",
			w: &Worker{probesByName: map[string]probe.Probe{
				"":  {Ports: "1", TransportProto: "tcp"},
				"2": {Ports: "1", TransportProto: "tcp"},
				"3": {Ports: "1", TransportProto: "tcp"},
				"5": {Ports: "1", TransportProto: "tcp"},
				"8": {Ports: "1", TransportProto: "tcp"}},
				expressionsByProbe: map[string][]byte{
					"":       []byte{},
					"2":      []byte{},
					"3":      []byte{},
					"5":      []byte{},
					"8":      []byte{},
					"qwfqwf": []byte{0x05},
				},
			},
			expected: 1,
		},
	}
	target := &dialer.Target{Protocol: "tcp", Port: 1}
	for _, tc := range testCases {
		m := tc.w.getMatchersByProbe(tc.probeName, target)
		if len(m) != tc.expected {
			t.Errorf("Expected: %d, Got: %d", tc.expected, len(m))
		}
	}
}
