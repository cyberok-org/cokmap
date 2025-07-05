package cokmap

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"plugin"
	"sync"
	"time"

	"github.com/cyberok-org/cokmap-api/types"
	ma "github.com/cyberok-org/cokmap/internal/matcher"

	"github.com/cyberok-org/cokmap/internal/dialer"
)

type Cokmap struct {
	exclude string
	config  *Config
}

func New(config *Config) *Cokmap {
	verbose := slog.LevelError
	switch config.Verbose {
	case 0:
		verbose = slog.LevelError
	case 1:
		verbose = slog.LevelWarn
	case 2:
		verbose = slog.LevelInfo
	case 3:
		verbose = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: verbose})))
	v := &Cokmap{
		config: config,
	}
	if config.input == nil {
		config.SetInput(inputTargets)
	}

	return v
}

func (v *Cokmap) Start(ctx context.Context) error {
	common, golden, err := v.initProbes()
	if err != nil {
		return fmt.Errorf("cannot load probes from probe files, error: %w, files: %v", err, v.config.ProbesFiles)
	}
	probesByName := v.parseProbesToMapKName(common, golden)

	err = v.probesFormat(common, golden)
	if err != nil {
		return fmt.Errorf("cannot load config probe files, error: %w, files: %v", err, v.config.PMCfgFile)
	}

	dialer := dialer.NewWorker(dialer.NewConfig(
		v.config.UseAllProbes,
		v.config.UseNULLProbe,
		v.config.CreateSummary,
		v.config.ProbeRarity,
		v.config.MaxProbes,
		v.config.ReadTimeout,
		v.config.SendTimeout,
		v.config.ConnectionTimeout,
	), common, golden)

	p, err := plugin.Open(v.config.ProductMatcherPlugin)
	if err != nil {
		return fmt.Errorf("fatal error while loading product matcher %s error %w", v.config.ProductMatcherPlugin, err)
	}

	loadMatchersPointer, err := p.Lookup("LoadMatchers")
	if err != nil {
		return fmt.Errorf("fatal error while loading function LoadMatchers product matcher error: %w", err)
	}

	loadMatchers, ok := loadMatchersPointer.(func(in io.Reader, timeout time.Duration) (types.Matchers, error))
	if !ok {
		return fmt.Errorf("unexpected type from plugin symbol: %T", loadMatchersPointer)
	}

	probesFile, err := os.Open(v.config.ProbesFiles[0])
	if err != nil {
		return fmt.Errorf("cannot load config probe files, error: %w, files: %v", err, v.config.PMCfgFile)
	}
	defer func() { _ = probesFile.Close() }()
	expressions, err := loadMatchers(probesFile, v.config.MatchReTimeout)
	if err != nil {
		return fmt.Errorf("cannot load expressions probe file, error: %w, files: %s", err, v.config.ProbesFiles)
	}
	expressionsByProbe, err := v.createExpressionsByProbe(expressions)
	if err != nil {
		return fmt.Errorf("cannot create expressions map : %w", err)
	}
	extracterProductsPointer, err := p.Lookup("ExtractProductsFromRunes")
	if err != nil {
		return fmt.Errorf("fatal error while loading function %s product matcher Plugin error %w", v.config.ProductMatcherPlugin, err)
	}

	extracterProducts, ok := extracterProductsPointer.(func(matchers types.Matchers, input []int32, ip string) ([]types.HostInfo, []error))
	if !ok {
		return fmt.Errorf("unexpected type from plugin symbol: %T", extracterProducts)
	}
	matcher := ma.NewWorker(
		v.config.CreateSummary,
		v.config.CreateProbesSummary,
		v.config.CreateErrorsSummary,
		expressionsByProbe,
		probesByName,
		extracterProducts,
	)

	start := time.Now()
	slog.Info("launching workers", "dial", v.config.DialWorkers, "match", v.config.MatchWorkers)
	err = v.launchWorkers(ctx, dialer, matcher)
	if err != nil {
		return fmt.Errorf("fatal cannot launch workers : %w", err)
	}

	v.outputSummary(matcher, dialer, start)

	return nil
}

func (v *Cokmap) launchWorkers(ctx context.Context, grabWorker *dialer.Worker, extractWorker *ma.Worker) error {
	res := make(chan *ma.ExtractResult)
	inTargets := make(chan dialer.Target, 1)
	grab := make(chan *dialer.DialResult, 1)

	var wgOutput sync.WaitGroup
	wgOutput.Add(1)
	go v.config.output(ctx, v.config.OutFile, v.config.BannerOutputSize, res, &wgOutput)

	var wgDialW sync.WaitGroup
	wgDialW.Add(v.config.DialWorkers)
	for range v.config.DialWorkers {
		go grabWorker.ProcessTargets(ctx, &wgDialW, inTargets, grab)
	}

	var wgMatchW sync.WaitGroup
	wgMatchW.Add(v.config.MatchWorkers)
	for range v.config.MatchWorkers {
		go extractWorker.ProcessBanners(ctx, &wgMatchW, grab, res)
	}

	if err := v.config.input(ctx, v.config.InFile, inTargets); err != nil {
		return err
	}
	close(inTargets)
	slog.Debug("close input targets")

	wgDialW.Wait()
	slog.Debug("dial workers end work")
	close(grab)

	wgMatchW.Wait()
	slog.Debug("match workers end work")
	close(res)

	wgOutput.Wait()

	return nil
}
