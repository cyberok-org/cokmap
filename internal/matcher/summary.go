package matcher

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	"github.com/cyberok-org/cokmap-api/types"
	"github.com/cyberok-org/cokmap/internal/dialer"
)

type ExtractSummary struct {
	logErrs   bool
	logProbes bool
	errors    []dialer.Errno
	services  sync.Map
	products  sync.Map
	probes    sync.Map
}

func (v *Worker) saveProductsSummary(grab *dialer.DialResult, extract []types.HostInfo) {
	if v.summary == nil {
		return
	}

	if v.summary.logErrs {
		if err := grab.Error; err != nil {
			var ve dialer.Error
			if errors.As(err, &ve) {
				v.summary.errors = append(v.summary.errors, ve.No)
			}
		}
	}

	uniq := make(map[string]struct{})
	for _, p := range extract {
		if _, ok := uniq[p.VendorProductName]; !ok && len(p.VendorProductName) > 0 {
			uniq[p.VendorProductName] = struct{}{}
			if counter, ok := v.summary.products.Load(p.VendorProductName); ok {
				a, ok := counter.(*atomic.Int64)
				if ok {
					a.Add(1)
				}
			} else {
				newatomic := &atomic.Int64{}
				newatomic.Store(1)
				v.summary.products.Store(p.VendorProductName, newatomic)
			}
		}
		if _, ok := uniq[p.Service]; !ok && len(p.Service) > 0 {
			uniq[p.Service] = struct{}{}
			if counter, ok := v.summary.services.Load(p.Service); ok {
				a, ok := counter.(*atomic.Int64)
				if ok {
					a.Add(1)
				}
			} else {
				newatomic := &atomic.Int64{}
				newatomic.Store(1)
				v.summary.services.Store(p.Service, newatomic)
			}
		}
	}

	if v.summary.logProbes {
		if counter, ok := v.summary.probes.Load(grab.Probe.Name); ok {
			a, ok := counter.(*atomic.Int64)
			if ok {
				a.Add(1)
			}
		} else {
			newatomic := &atomic.Int64{}
			newatomic.Store(1)
			v.summary.probes.Store(grab.Probe.Name, newatomic)
		}
	}
}

func (w *Worker) GetSummary() (services, products, probes, errors map[string]int64) {
	products = make(map[string]int64)
	services = make(map[string]int64)
	probes = make(map[string]int64)
	errors = make(map[string]int64)

	w.summary.services.Range(func(key interface{}, value interface{}) bool {
		count := value.(*atomic.Int64).Load()
		service := key.(string)
		if service == "" {
			service = "unknown"
		}
		services[service] = count
		return true
	})

	w.summary.products.Range(func(key interface{}, value interface{}) bool {
		count := value.(*atomic.Int64).Load()
		product := key.(string)
		printableProduct := strings.Builder{}
		for _, r := range product {
			if unicode.IsLetter(r) {
				printableProduct.WriteRune(r)
			}
		}
		products[printableProduct.String()] = count
		return true
	})

	w.summary.probes.Range(func(key interface{}, value interface{}) bool {
		count := value.(*atomic.Int64).Load()
		probeName := key.(string)
		if key.(string) != "" && count > 0 {
			probes[probeName] = count
		}
		return true
	})

	for _, errno := range w.summary.errors {
		errors[errno.String()]++
	}

	return
}
