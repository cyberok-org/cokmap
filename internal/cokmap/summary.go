package cokmap

import (
	"cokmap/internal/dialer"
	"cokmap/internal/matcher"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"
)

type sortedMapEntry struct {
	Key   string
	Value int64
}

func (v *Cokmap) outputSummary(matchWorker *matcher.Worker, dialWorker *dialer.Worker, start time.Time) {
	if !v.config.CreateSummary {
		return
	}
	end := time.Now()

	duration := end.Sub(start).String()
	total, tcp, udp := dialWorker.GetTargetsSummaryCounters()
	out, err := os.Create(v.config.SummaryFileName)
	if err != nil {
		slog.Error("failed to create output summary file")
		out = os.Stdin
	}

	statsResult := fmt.Sprintf("Scan stats:\n\ttargets processed: %d\n\tTCP banners received: %d\n\tUDP banners received: %d\n\ttime: %s\n",
		total, tcp, udp, duration)

	services, products, probes, errors := matchWorker.GetSummary()

	hostsResult := fmt.Sprintf("Protocols:\n\t%s\nProducts:\n\t%s",
		convertToString(sortMapByValue(services)), convertToString(sortMapByValue(products)))

	defer out.Close()

	if _, err := fmt.Fprintf(out, "%s\n%s\n", statsResult, hostsResult); err != nil {
		slog.Error("cannot store summary data to file", "error", err)
		return
	}
	v.createErrorsSummary(errors, out)
	v.createProbesSummary(probes, out)
	slog.Info("Summary created")
}

func (v *Cokmap) createErrorsSummary(errorsStat map[string]int64, out *os.File) {
	if !v.config.CreateErrorsSummary {
		return
	}
	sb := strings.Builder{}

	for err, count := range errorsStat {
		sb.WriteString(fmt.Sprintf("%s: %d\n\t", err, count))
	}

	if _, err := fmt.Fprintf(out, "\nErrors:\n\t%s", sb.String()); err != nil {
		slog.Error("cannot store errors summary to file", "error", err)
	}
}

func (v *Cokmap) createProbesSummary(probesStat map[string]int64, out *os.File) {
	if !v.config.CreateProbesSummary {
		return
	}

	sb := strings.Builder{}
	sorted := sortMapByValue(probesStat)

	for _, statLine := range sorted {
		sb.WriteString(statLine)
		sb.WriteString("\n\t")
	}

	if _, err := fmt.Fprintf(out, "\nProbes usage:\n\t%s", sb.String()); err != nil {
		slog.Error("cannot store probes usage to file", "error", err)
	}
}

func sortMapByValue(data map[string]int64) []string {
	entries := make([]sortedMapEntry, 0, len(data))
	for key, value := range data {
		entries = append(entries, sortedMapEntry{Key: key, Value: value})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Value > entries[j].Value
	})

	result := make([]string, 0, len(entries))
	for _, e := range entries {
		result = append(result, fmt.Sprintf("%s: %d", e.Key, e.Value))
	}

	return result
}

func convertToString(arr []string) string {
	sb := strings.Builder{}
	for _, s := range arr {
		sb.WriteString(fmt.Sprintf("%s\n\t", s))
	}

	return sb.String()
}
