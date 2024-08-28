package cokmap

import (
	"bufio"
	"cokmap/internal/dialer"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const targetPattern = `^(?P<ip>(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])):(?P<port>\d+)/?(?P<protocol>udp|tcp)?$`

func inputTargets(ctx context.Context, filename string, ch chan<- dialer.Target) error {
	source, err := os.Open(filename)
	if err != nil {
		return err
	}

	targetRegexp := regexp.MustCompile(targetPattern)

	reader := bufio.NewReader(source)
	defer source.Close()
	for {
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
			slog.Error("Wrong input target format", slog.String("error", errors.New(line).Error()))
			continue
		}

		ip := finds[1]
		port := finds[2]
		protocol := finds[3]
		if !(protocol == "tcp" || protocol == "udp") {
			protocol = "tcp"
		}
		portNum, _ := strconv.Atoi(port)

		ch <- dialer.Target{
			IP:       ip,
			Port:     portNum,
			Protocol: protocol,
		}
	}

	return nil
}
