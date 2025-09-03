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
	extractProducts    func(matchers any, banner []rune, socket string) ([][]byte, []error)
	expressionsByProbe map[string][]any
	probesByName       map[string]probe.Probe
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

type HostInfo struct {
	Probe       string `json:"probe"`
	Service     string `json:"service"`
	Regex       string `json:"regex"`
	FaviconHash string `json:"favicon_hash,omitempty"`
	SoftMatch   bool   `json:"softmatch"`
	Error       string `json:"error,omitempty"`
	Info[string]
}
type ExtractResult struct {
	*dialer.DialResult
	Products []HostInfo
}

func NewWorker(
	createSummary, probesSummary, errorsSummary bool,
	expressionsByProbe map[string][]any, probesByName map[string]probe.Probe,
	extractProducts func(matchers any, banner []rune, socket string) ([][]byte, []error),
) *Worker {
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
			extractedData, errRegexps := w.extractProducts(filtered, r, grab.IP)
			if len(errRegexps) > 0 {
				slog.Debug("got timeout errors while fetching products", "target", grab.GetAddress(), "errs", errRegexps)
			}
			if err != nil {
				grab.ErrorStr = err.Error()
			}
			var res []HostInfo
			for _, extract := range extractedData {
				var info *HostInfo
				_ = json.Unmarshal(extract, info)
				res = append(res, *info)
			}
			w.saveProductsSummary(grab, res)

			out <- &ExtractResult{
				grab,
				res,
			}
		}
	}
}

var tlsProbes = map[string]struct{}{
	"SSLSessionReq":    {},
	"TLSSessionReq":    {},
	"SSLv23SessionReq": {},
}

func isPossibleTLS(probeName, matchName string) bool {
	if _, ok := tlsProbes[probeName]; ok && matchName == "ssl" {
		return true
	}

	return false
}

func (w *Worker) ProcessBanner(ctx context.Context, grab *dialer.DialResult) (*ExtractResult, *dialer.Target) {

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
	extractedData, errRegexps := w.extractProducts(filtered, r, grab.IP)
	if len(errRegexps) > 0 {
		slog.Debug("got timeout errors while fetching products", "target", grab.GetAddress(), "errs", errRegexps)
	}
	if err != nil {
		grab.ErrorStr = err.Error()
	}
	var res []HostInfo
	for _, p := range extractedData {
		var info HostInfo
		_ = json.Unmarshal(p, info)
		if isPossibleTLS(grab.Name, info.Service) && !grab.Target.SecureUse {

			grab.Target.SecureUse = true
			slog.Debug("need to retry with tls connection", "grab", grab)
			return nil, grab.Target
		}
		res = append(res, info)
	}

	w.saveProductsSummary(grab, res)

	return &ExtractResult{
		grab,
		res,
	}, nil
}

func (w *Worker) getMatchersByProbe(probeName string, target *dialer.Target) []any {
	var filtered []any
	p, ok := w.expressionsByProbe[probeName]
	if !ok {
		for k, probe := range w.expressionsByProbe {
			probeData, ok := w.probesByName[k]
			if !ok || probeData.TransportProto != target.Protocol || !probeData.ContainsPort(target.Port) {
				continue
			}
			filtered = append(filtered, probe...)
		}
	} else {
		filtered = append(filtered, p...)
	}

	return filtered
}
