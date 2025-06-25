package matcher

import "cyberok.gitlab.yandexcloud.net/cok/tools/regexp2"

type TokenKind int

type Token struct {
	Kind  TokenKind `json:"kind"`
	Value string    `json:"value"`
	Args  []string  `json:"args"`
}

type Template []Token

type Protocol string

const (
	UnknownProtocol = Protocol("UnknownProtocol")
	TCP             = Protocol("TCP")
	UDP             = Protocol("UDP")
)

type Info[T any] struct {
	VendorProductName T   `json:"vendorproductname,omitempty"`
	Version           T   `json:"version,omitempty"`
	Info              T   `json:"info,omitempty"`
	Hostname          T   `json:"hostname,omitempty"`
	OS                T   `json:"os,omitempty"`
	DeviceType        T   `json:"devicetype,omitempty"`
	CPE               []T `json:"cpe,omitempty"`
}

type Matcher struct {
	Protocol Protocol
	Probe    string
	Service  string
	App      string
	Info[Template]
	Soft bool
	Re   *regexp2.Regexp
}

type Matchers []*Matcher

type MatchPattern struct {
	Regex string
	Flags string
}

type Match struct {
	Service string
	MatchPattern
	Info[Template]
	Soft bool
}

type ServiceProbe struct {
	Name        string
	Protocol    Protocol
	ProbeString string
	NoPayload   bool
	Matches     []Match
}

type HostInfo struct {
	Probe       string `json:"probe"`
	Service     string `json:"service"`
	Regex       string `json:"regex"`
	FaviconHash string `json:"favicon_hash,omitempty"`
	SoftMatch   bool   `json:"softmatch"`
	Error       string `json:"error,omitempty"`
	Info[string]
}
