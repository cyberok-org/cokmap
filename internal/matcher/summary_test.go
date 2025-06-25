package matcher

import (
	"testing"

	"github.com/cyberok-org/cokmap/internal/dialer"
	"github.com/cyberok-org/cokmap/internal/probe"
)

func TestSummarySave(t *testing.T) {
	type testCase struct {
		name             string
		data             *dialer.DialResult
		products         []HostInfo
		expectedServices int
		expectedVendors  int
		expectedErrors   int
		expectedProbes   int
	}

	testCases := []testCase{
		{
			name:     "Empty Products",
			data:     &dialer.DialResult{ScanData: &dialer.ScanData{}, Target: &dialer.Target{}},
			products: []HostInfo{},
		},
		{
			name: "Multiple Services",
			data: &dialer.DialResult{ScanData: &dialer.ScanData{}, Target: &dialer.Target{}},
			products: []HostInfo{
				{Service: "abc"},
				{Service: "abc"},
				{Service: "abc"},
				{Service: "ccc"},
				{Service: "def"},
			},
			expectedServices: 3,
		},
		{
			name: "All Same Service",
			data: &dialer.DialResult{ScanData: &dialer.ScanData{}, Target: &dialer.Target{}},
			products: []HostInfo{
				{Service: "abc"},
				{Service: "abc"},
				{Service: "abc"},
				{Service: "abc"},
			},
			expectedServices: 1,
		},
		{
			name: "All Same Service",
			data: &dialer.DialResult{ScanData: &dialer.ScanData{}, Target: &dialer.Target{}},
			products: []HostInfo{
				{Service: "abc", Info: Info[string]{VendorProductName: "vendor"}},
				{Service: "abc", Info: Info[string]{VendorProductName: "qwf"}},
				{Service: "abc", Info: Info[string]{VendorProductName: "vcx"}},
				{Service: "abc", Info: Info[string]{VendorProductName: "qzzzwf"}},
			},
			expectedServices: 1,
			expectedVendors:  4,
		},
		{
			name: "All Same Service",
			data: &dialer.DialResult{ScanData: &dialer.ScanData{}, Target: &dialer.Target{}},
			products: []HostInfo{
				{Service: "abc", Info: Info[string]{VendorProductName: "vendor"}},
				{Service: "abc", Info: Info[string]{VendorProductName: "qwf"}},
				{Service: "abc", Info: Info[string]{VendorProductName: "vcx"}},
				{Service: "abc", Info: Info[string]{VendorProductName: "qzzzwf"}},
			},
			expectedServices: 1,
			expectedVendors:  4,
		},
		{
			name:           "All Same Service",
			data:           &dialer.DialResult{ScanData: &dialer.ScanData{Error: dialer.Error{No: dialer.ErrConn}}, Target: &dialer.Target{}},
			expectedErrors: 1,
		},
		{
			name: "All Same Service",
			data: &dialer.DialResult{
				ScanData: &dialer.ScanData{
					Error: dialer.Error{No: dialer.ErrConn},
					Probe: probe.Probe{Name: "random"},
				},
				Target: &dialer.Target{},
			},
			expectedErrors: 1,
			expectedProbes: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWorker(true, true, true, nil, nil, nil)
			w.saveProductsSummary(tc.data, tc.products)
			services, products, probes, errors := w.GetSummary()
			if len(services) != tc.expectedServices {
				t.Errorf("Expected %d services, got %d", tc.expectedServices, len(services))
			}
			if len(products) != tc.expectedVendors {
				t.Errorf("Expected %d Vendors, got %d", tc.expectedVendors, len(products))
			}
			if len(errors) != tc.expectedErrors {
				t.Errorf("Expected %d Errors, got %d", tc.expectedErrors, len(errors))
			}
			if len(probes) != tc.expectedProbes {
				t.Errorf("Expected %d Probes, got %d", tc.expectedProbes, len(probes))
			}
		})
	}
}
