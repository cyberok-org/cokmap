package cokmap

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/cyberok-org/cokmap/internal/probe"
	"github.com/cyberok-org/cokmap/pkg/matcher"
)

func (v *Cokmap) probesFormat(common, golden []probe.Probe) error {
	if v.config.PMCfgFile == "" {
		slog.Info("warning: Product Matcher will try parse only string format response")
		return nil
	}
	slog.Info("Product Matcher with probes configuration enabled")
	f, err := os.Open(v.config.PMCfgFile)
	if err != nil {
		return err
	}
	probeByProto, err := parseIniFile(f)
	if err != nil {
		return err
	}
	for _, cfgP := range probeByProto {
		if cfgP.Hex {
			probeWithService := strings.Split(cfgP.Probe, "/")
			if len(probeWithService) < 2 {
				continue
			}
			for i, p := range common {
				if p.Name == "NULL" {
					continue
				}
				if p.Name == probeWithService[0] {
					common[i].HexFormat = true
					slog.Info("Cokmap will try hex format for", "probe", fmt.Sprintf("%s %s", p.TransportProto, p.Name))
					continue
				}
				if _, ok := p.Services[probeWithService[1]]; ok {
					common[i].HexFormat = true
					slog.Info("Cokmap will try hex format for", "probe", fmt.Sprintf("%s %s", p.TransportProto, p.Name))
				}
			}
			for i, p := range golden {
				if p.Name == "NULL" {
					continue
				}
				if p.Name == probeWithService[0] {
					golden[i].HexFormat = true
					slog.Info("Cokmap will try hex format for", "probe", fmt.Sprintf("%s %s", p.TransportProto, p.Name))
					continue
				}
				if _, ok := p.Services[probeWithService[1]]; ok {
					golden[i].HexFormat = true
					slog.Info("Cokmap will try hex format for", "probe", fmt.Sprintf("%s %s", p.TransportProto, p.Name))
				}
			}
		}
	}

	return nil
}

func (v *Cokmap) setProbesFromContent(content string, isGoldenProbes bool) ([]probe.Probe, error) {
	var probes []probe.Probe

	var lines []string
	linesTemp := strings.Split(content, "\n")
	for _, lineTemp := range linesTemp {
		lineTemp = strings.TrimSpace(lineTemp)
		if lineTemp == "" || strings.HasPrefix(lineTemp, "#") {
			continue
		}
		lines = append(lines, lineTemp)
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("failed to read nmap-service-probes file for probe data, 0 lines read")
	}
	c := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			c += 1
		}
		if c > 1 {
			return nil, fmt.Errorf("only 1 Exclude directive is allowed in the nmap-service-probes file")
		}
	}
	l := lines[0]
	if !(strings.HasPrefix(l, "Exclude ") || strings.HasPrefix(l, "Probe ")) {
		return nil, fmt.Errorf("parse error on nmap-service-probes file: line was expected to begin with \"Probe \" or \"Exclude \"")
	}
	if c == 1 {
		v.exclude = l[len("Exclude")+1:]
		lines = lines[1:]
	}
	content = strings.Join(lines, "\n")
	content = "\n" + content

	probeParts := strings.Split(content, "\nProbe")
	probeParts = probeParts[1:]

	for _, probePart := range probeParts {
		probe := probe.Probe{}
		err := probe.FromString(probePart)
		if err != nil {
			slog.Warn("cannot parse from string probe part", err.Error(), probePart)
			continue
		}
		probe.Golden = isGoldenProbes
		probes = append(probes, probe)
	}

	return probe.SortProbesByRarity(probes), nil
}

func (v *Cokmap) parseProbesToMapKName(common, golden []probe.Probe) map[string]probe.Probe {
	var probesMap = map[string]probe.Probe{}
	for _, probe := range common {
		probesMap[probe.Name] = probe
	}
	for _, probe := range golden {
		probesMap[probe.Name] = probe
	}

	return probesMap
}

func (v *Cokmap) initProbes() (common, golden []probe.Probe, err error) {
	for i, f := range v.config.ProbesFiles {
		probeFile, err := os.Open(f)
		if err != nil {
			slog.Error("Cokmap init", "cannot open the file", err)
			return nil, nil, err
		}

		data, err := io.ReadAll(probeFile)
		if err != nil {
			slog.Error("Cokmap init", "cannot read the file", err)
			return nil, nil, err
		}
		probeFile.Close()

		parsed, err := v.setProbesFromContent(string(data), i > 0)
		if err != nil {
			return nil, nil, err
		}
		if i > 0 {
			golden = parsed
		} else {
			common = parsed
		}
	}

	return
}

func (v *Cokmap) createExpressionsByProbe(expressions matcher.Matchers) (map[string]matcher.Matchers, error) {
	if len(expressions) == 0 {
		return nil, fmt.Errorf("expressions must be not nil and empty")
	}
	allocatorMap := make(map[string]int, len(expressions))
	for _, e := range expressions {
		if e.Soft && !v.config.EnabledSoftMatch {
			continue
		}
		allocatorMap[e.Probe] += 1
	}
	expressionsByProbe := make(map[string]matcher.Matchers, len(allocatorMap))
	for _, e := range expressions {
		if e.Soft && !v.config.EnabledSoftMatch {
			continue
		}
		if len(expressionsByProbe[e.Probe]) == 0 {
			expressionsByProbe[e.Probe] = make(matcher.Matchers, 0, allocatorMap[e.Probe])
		}
		expressionsByProbe[e.Probe] = append(expressionsByProbe[e.Probe], e)
	}
	return expressionsByProbe, nil
}
