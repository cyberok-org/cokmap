package main

import (
	"flag"
	"time"

	"github.com/cyberok-org/cokmap/internal/cokmap"
)

var (
	// TODO: add scan retries
	// scanRetries  = flag.Int("r", 0, "how many retries to dial connection")
	verbose      = flag.Int("v", 0, "Output more information during service scanning 0=Error 1=Warning 2=Info 3=Debug")
	dialWorkers  = flag.Int("tr", 10, "process numbers using during scanning")
	matchWorkers = flag.Int("tm", 10, "process numbers using during parsing")

	pmPlugin           = flag.String("plugin", "../plugin/pm.so", "Name of product matcher dynamic plugin file")
	probesCfg          = flag.String("probes-cfg", "", "ini file for probes specifiations, sets which regular expression have different format, which indicates where need to convert banner")
	scanProbeFile      = flag.String("n", "./nmap-service-probes", "A flat file to store the version detection probes and match strings")
	probeRarity        = flag.Int("pr", 7, "Sets the intensity level of a version scan to the specified value")
	probesCount        = flag.Int("pc", 5, "Sets the count of sending probes by rarity, dont disable others probes by ports, usefull for quickiest runtime")
	scanSendTimeout    = flag.Int("cst", 5, "Set connection send timeout in seconds")
	scanReadTimeout    = flag.Int("crt", 5, "Set connection read timeout in seconds")
	connTimeout        = flag.Int("ct", 5, "Set connection to host timeout in seconds")
	matchReTimeout     = flag.Int("ret", 1, "Set regexp match timeout in seconds")
	enabledSoftMatch   = flag.Bool("fr", true, "Enable softmatch parsing")
	scanProbeFileExtra = flag.String("n-extra", "", "Extra, golden probes to expand\"nmap-service-probes\"")

	stat       = flag.Bool("stat", true, "Save summary grab results")
	errorsStat = flag.Bool("err-stat", true, "Save errors summary")
	probesStat = flag.Bool("p-stat", true, "Save successful-probes summary")
	fileStat   = flag.String("file-stat-name", "summary_cokmap_result", "Save successful-match summary")

	useAllProbes = flag.Bool("all-probes", false, "Use all probes after failed filtered probes (default false)")
	useNULLProbe = flag.Bool("use-NULL", false, "Use NULL probe in dialer service (default false)")

	inFileName       = flag.String("i", "-", "Input filename, use - for stdin format is ip:port/protocol")
	outFileName      = flag.String("o", "-", "Output filename, use - for stdout")
	bannerOutputSize = flag.Int("bs", -1, "Output banner limit size: negative int = fullsize, 0 = without banner (default fullsize)")
)

func NewCfg() *cokmap.Config {
	probeFiles := []string{*scanProbeFile}
	if *scanProbeFileExtra != "" {
		probeFiles = []string{*scanProbeFile, *scanProbeFileExtra}
	}
	config := &cokmap.Config{
		Verbose:              *verbose,
		ProbeRarity:          *probeRarity,
		MaxProbes:            *probesCount,
		SendTimeout:          time.Duration(*scanSendTimeout) * time.Second,
		ReadTimeout:          time.Duration(*scanReadTimeout) * time.Second,
		ConnectionTimeout:    time.Duration(*connTimeout) * time.Second,
		MatchReTimeout:       time.Duration(*matchReTimeout) * time.Second,
		UseAllProbes:         *useAllProbes,
		UseNULLProbe:         *useNULLProbe,
		ProductMatcherPlugin: *pmPlugin,
		DialWorkers:          *dialWorkers,
		MatchWorkers:         *matchWorkers,
		EnabledSoftMatch:     *enabledSoftMatch,
		PMCfgFile:            *probesCfg,
		CreateSummary:        *stat,
		CreateProbesSummary:  *probesStat,
		CreateErrorsSummary:  *errorsStat,
		SummaryFileName:      *fileStat,
		ProbesFiles:          probeFiles,
		InFile:               *inFileName,
		OutFile:              *outFileName,
		BannerOutputSize:     *bannerOutputSize,
	}

	config.SetOutPut(output)
	config.SetInput(inputTargets)
	return config
}
