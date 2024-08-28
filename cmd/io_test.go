package main

import (
	"bytes"
	"cokmap/internal/dialer"
	"cokmap/internal/matcher"
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"
)

func Test_output(t *testing.T) {
	type testCase struct {
		outputFunc  func(dataLen int, ctx context.Context, outCh chan *matcher.ExtractResult, wg *sync.WaitGroup)
		inputData   []byte
		bsparameter int
		expected    []byte
	}
	outFile := "./test_out"
	testFunc := func(datalen int, ctx context.Context, outCh chan *matcher.ExtractResult, wg *sync.WaitGroup) {
		go output(ctx, outFile, datalen, outCh, wg)
	}
	testCases := []testCase{
		{
			outputFunc:  testFunc,
			inputData:   []byte("correctwgqwgqwgwqgwqg"),
			bsparameter: 7,
			expected:    []byte("correct"),
		},
		{
			outputFunc:  testFunc,
			inputData:   []byte("correctwgqwgqwgwqgwqg"),
			bsparameter: 0,
			expected:    []byte{},
		},
		{
			outputFunc:  testFunc,
			inputData:   []byte("correctwgqwgqwgwqgwqg"),
			bsparameter: len("correctwgqwgqwgwqgwqg"),
			expected:    []byte("correctwgqwgqwgwqgwqg"),
		},
		{
			outputFunc:  testFunc,
			inputData:   []byte("correctwgqwgqwgwqgwqg"),
			bsparameter: 125125125,
			expected:    []byte("correctwgqwgqwgwqgwqg"),
		},
	}
	for i, tc := range testCases {
		// launch outputfunc
		outCh := make(chan *matcher.ExtractResult)
		wg := sync.WaitGroup{}
		wg.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		tc.outputFunc(tc.bsparameter, ctx, outCh, &wg)

		testRes := new(matcher.ExtractResult)
		sd := new(dialer.ScanData)
		sd.Response = string(tc.inputData)
		testRes.DialResult = &dialer.DialResult{
			ScanData: sd,
		}
		outCh <- testRes
		// compare result
		time.Sleep(time.Second)
		cancel()
		close(outCh)
		data, _ := os.ReadFile(outFile)
		if len(data) == 0 {
			t.Errorf("no data received from output test case %d", i)
		}
		outRes := &dialer.ScanData{}
		err := json.Unmarshal(data, outRes)
		if err != nil {
			t.Errorf("data should be cokmap.ScanData type test case %d", i)
		}
		if !bytes.Equal([]byte(outRes.Response), tc.expected) {
			t.Errorf("response should be %s got %s", tc.expected, outRes.Response)
		}
		os.Remove(outFile)
	}
}
