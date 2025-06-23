package matcher

import (
	"cokmap/internal/dialer"
	"cokmap/internal/probe"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
)

type Worker struct {
	summary            *ExtractSummary
	extractProducts    func(matchers any, input []rune, ip string) ([]any, []error)
	expressionsByProbe map[string][]map[string]any
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

func NewWorker(
	createSummary, probesSummary, errorsSummary bool,
	expressionsByProbe map[string][]map[string]any, probesByName map[string]probe.Probe,
	extractProducts func(matchers any, input []rune, ip string) ([]any, []error),
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
			extractedData, _ := w.extractProducts(filtered, r, grab.IP)
			if err != nil {
				grab.ErrorStr = err.Error()
			}
			hi, err := convertToHostInfo(extractedData)
			if err != nil {
				slog.Warn("got error from parsing response", "target", grab.IP, "error", err.Error())
				return
			}
			w.saveProductsSummary(grab, hi)

			out <- &ExtractResult{
				grab,
				hi,
			}
		}
	}
}

func (w *Worker) getMatchersByProbe(probeName string, target *dialer.Target) []map[string]any {
	var filtered []map[string]any
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

func convertToHostInfo(extractedData []any) ([]HostInfo, error) {
	var hostInfos []HostInfo
	for _, data := range extractedData {

		resultMap, ok := data.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("неверный тип данных: ожидается map[string]any, получено %T", data)
		}

		infoMap, ok := resultMap["Info"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("неверный тип поля Info: ожидается map[string]any, получено %T", resultMap["Info"])
		}

		var cpe []string
		if cpeAny, ok := infoMap["CPE"].([]any); ok {
			for _, c := range cpeAny {
				if cStr, ok := c.(string); ok {
					cpe = append(cpe, cStr)
				}
			}
		}

		hostInfo := HostInfo{
			Probe:     getStringField(resultMap, "Probe"),
			Service:   getStringField(resultMap, "Service"),
			SoftMatch: getBoolField(resultMap, "SoftMatch"),
			Error:     getStringField(resultMap, "Error"),
			Info: Info[string]{
				VendorProductName: getStringField(infoMap, "VendorProductName"),
				Version:           getStringField(infoMap, "Version"),
				OS:                getStringField(infoMap, "OS"),
				DeviceType:        getStringField(infoMap, "DeviceType"),
				CPE:               cpe,
			},
		}

		hostInfos = append(hostInfos, hostInfo)
	}
	return hostInfos, nil
}

func getStringField(m map[string]any, key string) string {
	if val, ok := m[key].(string); ok {
		return val
	}
	return ""
}

func getBoolField(m map[string]any, key string) bool {
	if val, ok := m[key].(bool); ok {
		return val
	}
	return false
}
