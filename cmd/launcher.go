package main

import (
	"bufio"
	"cokmap/internal/cokmap"
	"cokmap/internal/dialer"
	"cokmap/internal/matcher"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const targetPattern = `^(?P<ip>(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])):(?P<port>\d+)/?(?P<protocol>udp|tcp|tls|http|https|ssl)?$`

func start(ctx context.Context, cfg *cokmap.Config) {
	ck := cokmap.New(cfg)
	// for profiler
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	err := ck.Start(ctx)
	if err != nil {
		log.Fatal(err)
	}
}

func inputTargets(ctx context.Context, targetsFile string, ch chan<- dialer.Target) error {
	var source *os.File
	switch targetsFile {
	case "-":
		slog.Info("CLI mod active - input address to check products - press cancel + enter for escape from the app")
		source = os.Stdin
	default:
		inFileT, err := os.Open(targetsFile)
		slog.Info("Proccessing targets from file")
		if err != nil {
			return err
		}
		source = inFileT
	}
	defer slog.Info("input handler end his work")
	defer source.Close()
	targetRegexp, err := regexp.Compile(targetPattern)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(source)
	for {
		// if stdin will empty - go func will keep alive until input from cli
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		finds := targetRegexp.FindStringSubmatch(line)
		if len(finds) == 0 {
			slog.Error("Wrong input target format", "line", errors.New(line))
			continue
		}

		ip := finds[1]
		port := finds[2]
		protocol := finds[3]

		security := isSecureProto(protocol)
		protocol = supportedProtocol(protocol)

		portNum, _ := strconv.Atoi(port)

		ch <- dialer.Target{
			IP:        ip,
			Port:      portNum,
			Protocol:  protocol,
			SecureUse: security,
		}
	}

	return nil
}

func supportedProtocol(protocol string) (transportLayerProto string) {
	switch protocol {
	case "udp":
		return protocol
	default:
		return "tcp"
	}
}

func isSecureProto(protocol string) bool {
	switch protocol {
	case "https", "tls", "ssl":
		return true
	default:
		return false
	}
}

func output(ctx context.Context, outFile string, bannerOutputSize int, ch <-chan *matcher.ExtractResult, wg *sync.WaitGroup) {
	defer wg.Done()
	var dest *os.File
	var err error
	switch outFile {
	case "-":
		dest = os.Stdout
	default:
		dest, err = os.Create(outFile)
		if err != nil {
			log.Fatal(err)
		}
	}

	defer slog.Info("all targets proccessed")
	defer dest.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-ch:
			if !ok {
				return
			}

			offset := 0
			switch {
			case bannerOutputSize < 0 || bannerOutputSize > len(result.Response):
				offset = len(result.Response)
			default:
				offset = bannerOutputSize
			}

			result.Response = result.Response[:offset]

			encodeJSON, err := json.Marshal(result)
			if err != nil {
				continue
			}
			dest.WriteString(string(encodeJSON))
			dest.Write([]byte{0x0a})
		}
	}
}
