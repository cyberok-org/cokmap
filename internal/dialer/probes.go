package dialer

import (
	"strings"

	"github.com/cyberok-org/cokmap/internal/probe"
)

func (w *Worker) selectProbes_old(target *Target) []probe.Probe {
	var selectedProbes []probe.Probe
	lastSelectedId := 0
	targetTransportProto := strings.ToLower(target.Protocol)

	for i, probe := range w.common {
		if len(selectedProbes) >= w.config.probesLimit {
			break
		}
		if probe.Rarity > w.config.rarityLimit {
			break
		}
		if strings.EqualFold(strings.ToLower(probe.TransportProto), targetTransportProto) {
			selectedProbes = append(selectedProbes, probe)
			lastSelectedId = i
		}
	}

	switch {
	case len(w.golden) > 0:
		for _, p := range w.golden {
			if p.Rarity > w.config.rarityLimit {
				break
			}

			if strings.EqualFold(strings.ToLower(p.TransportProto), targetTransportProto) {
				selectedProbes = append(selectedProbes, p)
			}
		}
	default:
		for _, probe := range w.common[lastSelectedId:] {
			if probe.ContainsPort(target.Port) &&
				strings.EqualFold(strings.ToLower(probe.TransportProto), targetTransportProto) {
				selectedProbes = append(selectedProbes, probe)
			}
		}
	}

	if w.config.useNullProbe {
		selectedProbes = append(selectedProbes, *w.nullProbe)
	}

	return selectedProbes
}

func (w *Worker) selectProbes(target *Target) []probe.Probe {

	probesLimit := w.config.probesLimit
	rarityLimit := w.config.rarityLimit

	filterProbes := func(probeList []probe.Probe) (filtered, other []probe.Probe) {

		for _, probe := range probeList {
			// if _, used := target.UsedProbes[probe.Name]; used {
			// 	continue
			// }

			if probe.Rarity > rarityLimit {
				continue
			}

			if !strings.EqualFold(probe.TransportProto, target.Protocol) {
				continue
			}

			containsPort := probe.ContainsPort
			if target.SecureUse {
				containsPort = probe.ContainsSSLPort
			}

			if !containsPort(target.Port) {
				other = append(other, probe)
				continue
			}

			filtered = append(filtered, probe)
		}
		return filtered, other
	}

	goldenFiltered, goldenOther := filterProbes(w.golden)
	probe.SortProbesByRarity(goldenFiltered)
	if len(goldenFiltered) >= probesLimit {
		return goldenFiltered[:probesLimit]
	}

	commonFiltered, commonOther := filterProbes(w.common)
	probe.SortProbesByRarity(commonFiltered)
	remaining := probesLimit - len(goldenFiltered)
	if len(commonFiltered) >= remaining {
		return append(goldenFiltered, commonFiltered[:remaining]...)
	}

	selected := make([]probe.Probe, 0, probesLimit)
	selected = append(selected, goldenFiltered...)
	selected = append(selected, commonFiltered...)

	probe.SortProbesByRarity(goldenOther)
	remaining = probesLimit - len(selected)
	if len(goldenOther) >= remaining {
		return append(selected, goldenOther[:remaining]...)
	}
	selected = append(selected, goldenOther...)

	probe.SortProbesByRarity(commonOther)
	remaining = probesLimit - len(selected)
	if len(commonOther) >= remaining {
		return append(selected, commonOther[:remaining]...)
	}

	return append(selected, commonOther...)
}

func (w *Worker) getAllRemainingProbes(proto string, blacklist map[string]struct{}) []probe.Probe {
	selected := []probe.Probe{}
	for _, probe := range w.common {
		if _, ok := blacklist[probe.Name]; ok {
			continue
		}
		if strings.EqualFold(strings.ToLower(probe.TransportProto), proto) {
			selected = append(selected, probe)
		}
	}
	return selected
}
