package cokmap

import (
	"bufio"
	"context"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyberok-org/cokmap/internal/dialer"
	"github.com/cyberok-org/cokmap/internal/matcher"
)

type Config struct {
	ProbeRarity          int
	MaxProbes            int
	Verbose              int
	DialWorkers          int
	MatchWorkers         int
	RetryCount           int
	BannerOutputSize     int
	MatchReTimeout       time.Duration
	ConnectionTimeout    time.Duration
	SendTimeout          time.Duration
	ReadTimeout          time.Duration
	ProductMatcherPlugin string
	InFile               string
	OutFile              string
	PMCfgFile            string
	SummaryFileName      string
	ProbesFiles          []string
	UseNULLProbe         bool
	UseAllProbes         bool
	SSLAlwaysTry         bool
	EnabledSoftMatch     bool
	CreateSummary        bool
	CreateProbesSummary  bool
	CreateErrorsSummary  bool
	output               Output
	input                InputTargets
}

type Output func(ctx context.Context, filename string, bannerSizeLimit int, ch <-chan *matcher.ExtractResult, wg *sync.WaitGroup)

// Target.Protocol can be only tcp/udp
type InputTargets func(ctx context.Context, filename string, ch chan<- dialer.Target) error

func (c *Config) SetInput(f InputTargets) {
	c.input = f
}

func (c *Config) SetOutPut(f Output) {
	c.output = f
}

type probeСfg struct {
	Probe string
	Hex   bool
}

func parseIniFile(file io.Reader) (map[string]probeСfg, error) {
	result := make(map[string]probeСfg)
	scanner := bufio.NewScanner(file)

	var currentName string
	var currentProbe probeСfg
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if currentName != "" && currentProbe != (probeСfg{}) {
				result[currentName] = currentProbe
			}
			currentName = strings.Trim(line, "[]")
			currentProbe = probeСfg{}
		} else if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, "\"")

				switch key {
				case "name":
					currentName = value
				case "product-matchers":
					currentProbe.Probe = value
				case "hex":
					hexVal, err := strconv.ParseBool(value)
					if err == nil {
						currentProbe.Hex = hexVal
					}
				}
			}
		}
	}

	if currentName != "" && currentProbe != (probeСfg{}) {
		result[currentName] = currentProbe
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
