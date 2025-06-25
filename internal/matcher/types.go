package matcher

import "cyberok.gitlab.yandexcloud.net/cok/tools/regexp2"

type tokenKind int

type Token struct {
	Kind  tokenKind `json:"kind"`
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
	Info[string]
	Soft bool
}

type ServiceProbe struct {
	Name        string
	Protocol    Protocol
	ProbeString string
	NoPayload   bool
	Matches     []Match
}
