package dialer

import (
	"strings"

	"github.com/cyberok-org/cokmap/internal/probe"
)

func (w *Worker) selectProbes(target *Target) []probe.Probe {
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
