package matcher

import (
	"context"
	"encoding/hex"
	"log/slog"
	"sync"

	"github.com/cyberok-org/cokmap-api/types"
	"github.com/cyberok-org/cokmap/internal/dialer"
	"github.com/cyberok-org/cokmap/internal/probe"
)

type Worker struct {
	summary            *ExtractSummary
	extractProducts    func(matchers types.Matchers, banner []rune, socket string) ([]types.HostInfo, []error)
	expressionsByProbe map[string]types.Matchers
	probesByName       map[string]probe.Probe
}
type ExtractResult struct {
	*dialer.DialResult
	Products []types.HostInfo
}

func NewWorker(
	createSummary, probesSummary, errorsSummary bool,
	expressionsByProbe map[string]types.Matchers, probesByName map[string]probe.Probe,
	extractProducts func(matchers types.Matchers, banner []rune, socket string) ([]types.HostInfo, []error),
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
			w.saveProductsSummary(grab, extractedData)

			out <- &ExtractResult{
				grab,
				extractedData,
			}
		}
	}
}

func (w *Worker) getMatchersByProbe(probeName string, target *dialer.Target) types.Matchers {
	var filtered types.Matchers
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
