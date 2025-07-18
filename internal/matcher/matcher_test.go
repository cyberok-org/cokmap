package matcher

import (
	"testing"

	"github.com/cyberok-org/cokmap-api/types"
	"github.com/cyberok-org/cokmap/internal/dialer"
	"github.com/cyberok-org/cokmap/internal/probe"
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
			w:         &Worker{expressionsByProbe: map[string]types.Matchers{"NULL": {&types.Matcher{}}}},
			expected:  1,
		},
		{ // want to get all matchers
			probeName: "qwfqwf",
			w: &Worker{probesByName: map[string]probe.Probe{
				"":  {Ports: "1", TransportProto: "tcp"},
				"2": {Ports: "1", TransportProto: "tcp"},
				"3": {Ports: "1", TransportProto: "tcp"},
				"5": {Ports: "1", TransportProto: "tcp"},
				"8": {Ports: "1", TransportProto: "tcp"},
			},
				expressionsByProbe: map[string]types.Matchers{
					"":       {},
					"2":      {},
					"3":      {},
					"5":      {},
					"8":      {},
					"qwfqwf": {&types.Matcher{}},
				},
			},
			expected: 1,
		},
	}
	target := &dialer.Target{Protocol: "tcp", Port: 1}
	for _, tc := range testCases {
		m := tc.w.getMatchersByProbe(tc.probeName, target)
		if len(m) != tc.expected {
			t.Errorf("Expected: %d, Got: %d name %s", tc.expected, len(m), tc.probeName)
		}
	}
}
