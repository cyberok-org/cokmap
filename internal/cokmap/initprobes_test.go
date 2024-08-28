package cokmap

import (
	"cokmap/internal/probe"
	"io"
	"os"
	"reflect"
	"testing"
	"github.com/stretchr/testify/require"
)

func TestParseProbes(t *testing.T) {
	v := New(&Config{ProbesFiles: []string{"./test_files/probes"}})
	common, _, err := v.initProbes()
	require.NoError(t, err)
	require.Equal(t, 3, len(common))
}

func TestFormatProbes(t *testing.T) {
	v := &Cokmap{
		config: &Config{
			PMCfgFile: "./test_files/test.ini",
		},
	}
	probes := []probe.Probe{
		{
			Name: "DNSVersionBindReq",
		},
		{
			Services: map[string]struct{}{
				"ms-wbt-server": {},
			},
		},
	}
	err := v.probesFormat(probes, nil)
	if err != nil {
		t.Errorf("file cannot be open to check test result")
	}
	if !probes[0].HexFormat || !probes[1].HexFormat {
		t.Error("probes must can be hex formated")
	}
}
func TestParseIniFile(t *testing.T) {
	iniFile, err := os.Open("./test_files/test.ini")
	if err != nil {
		t.Error(err)
	}
	defer iniFile.Close()
	type args struct {
		file io.Reader
	}
	tests := []struct {
		name string
		args args
		want map[string]probeСfg
	}{
		{name: "valid test", args: args{file: iniFile}, want: map[string]probeСfg{
			"http":       {"GetRequest/*", false},
			"http_tls":   {"GetRequest/*", false},
			"http_ssl":   {"GetRequest/*", false},
			"banner":     {"GenericLines/*", false},
			"banner_tls": {"GenericLines/*", false},
			"mysql":      {"NULL/mysql", false},
			"rdp":        {"*/ms-wbt-server", true},
			"postgres":   {"GenericLines/postgresql,SMBProgNeg/postgresql", false},
			"mssql":      {"ms-sql-s/ms-sql-s", false},
			"redis":      {"redis-server/redis", false},
			"mongodb":    {"mongodb/mongodb", false},
			"oracle":     {"oracle-tns/*", false},
			"dns":        {"DNSVersionBindReq/*,DNSVersionBindReqTCP/*", true},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIniFile(tt.args.file)
			if err != nil {
				t.Errorf("parseIniFile() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseIniFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
