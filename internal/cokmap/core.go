package cokmap

import (
	"cokmap/internal/dialer"
	"cokmap/internal/matcher"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"plugin"
	"sync"
	"time"
)

type Cokmap struct {
	exclude string
	config  *Config
}

var (
	tagLoadMatchers    = "LoadMatchers"
	tagExtractProducts = "ExtractProductsFromRunes"
)

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

type PluginInterface interface {
	LoadMatchers(in io.Reader, timeout time.Duration) (interface{}, error)
	ExtractProductsFromRunes(matchers interface{}, input []rune, ip string) ([]interface{}, []error)
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

	symPlugin, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("ошибка поиска символа plugin: %v", err)
	}

	pluginInstance, ok := symPlugin.(PluginInterface)
	if !ok {
		return fmt.Errorf("неверный тип плагина %T", pluginInstance)
	}

	probesFile, err := os.Open(v.config.ProbesFiles[0])
	if err != nil {
		return fmt.Errorf("cannot load config probe files, error: %w, files: %v", err, v.config.PMCfgFile)
	}

	expressions, err := pluginInstance.LoadMatchers(probesFile, v.config.MatchReTimeout)
	// expressions, err := (lm)(probesFile, v.config.MatchReTimeout)
	if err != nil {
		return fmt.Errorf("cannot load expressions probe file, error: %w, files: %s", err, v.config.ProbesFiles)
	}
	probesFile.Close()

	ma, ok := expressions.([]map[string]interface{})
	if !ok {
		return fmt.Errorf("cannot convert expressions to matchers.Matchers")
	}

	expressionsByProbe, err := v.createExpressionsByProbe(ma)
	if err != nil {
		return fmt.Errorf("cannot create expressions map : %w", err)
	}

	// extractProductFromRunesSymbol, err := p.Lookup(tagExtractProducts)
	// if err != nil {
	// 	return fmt.Errorf("fatal error while loading func %s from product matcher %s error %w", tagExtractProducts, v.config.ProductMatcherPlugin, err)
	// }

	// Assert that the symbol is a function with the appropriate signature
	// ep, ok := .(func(matchers []map[string]any, input []rune, ip string) ([]matcher.HostInfo, []error))
	// if !ok {
	// 	return fmt.Errorf("unexpected type from plugin symbol: %T", extractProductFromRunesSymbol)
	// }

	matcher := matcher.NewWorker(
		v.config.CreateSummary,
		v.config.CreateProbesSummary,
		v.config.CreateErrorsSummary,
		expressionsByProbe,
		probesByName,
		pluginInstance.ExtractProductsFromRunes,
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

func (v *Cokmap) launchWorkers(ctx context.Context, grabWorker *dialer.Worker, extractWorker *matcher.Worker) error {
	res := make(chan *matcher.ExtractResult)
	inTargets := make(chan dialer.Target)
	grab := make(chan *dialer.DialResult, v.config.DialWorkers*4)

	wgOutput := sync.WaitGroup{}
	wgOutput.Add(1)
	go v.config.output(ctx, v.config.OutFile, v.config.BannerOutputSize, res, &wgOutput)

	var wgDialW sync.WaitGroup
	var wgMatchW sync.WaitGroup
	wgDialW.Add(v.config.DialWorkers)
	wgMatchW.Add(v.config.MatchWorkers)

	for range v.config.DialWorkers {
		go extractWorker.ProcessBanners(ctx, &wgMatchW, grab, res)
	}

	for range v.config.MatchWorkers {
		go grabWorker.ProcessTargets(ctx, &wgDialW, inTargets, grab)
	}

	if err := v.config.input(ctx, v.config.InFile, inTargets); err != nil {
		return err
	}

	close(inTargets)
	wgDialW.Wait()
	slog.Debug("dial workers end work")
	close(grab)
	wgMatchW.Wait()
	slog.Debug("match workers end work")
	close(res)
	wgOutput.Wait()

	return nil
}
