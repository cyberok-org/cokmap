package matchers

import "cyberok.gitlab.yandexcloud.net/cok/tools/regexp2"

type Template []Token

type Token struct {
	Kind  tokenKind `json:"kind"`
	Value string    `json:"value"`
	Args  []string  `json:"args"`
}

type tokenKind int
type Protocol string

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

type ExtractResult struct {
	Probe       string `json:"probe"`
	Service     string `json:"service"`
	Regex       string `json:"regex"`
	FaviconHash string `json:"favicon_hash,omitempty"`
	SoftMatch   bool   `json:"softmatch"`
	Error       string `json:"error,omitempty"`
	Info[string]
}

type Info[T any] struct {
	VendorProductName T   `json:"vendorproductname,omitempty"`
	Version           T   `json:"version,omitempty"`
	Info              T   `json:"info,omitempty"`
	Hostname          T   `json:"hostname,omitempty"`
	OS                T   `json:"os,omitempty"`
	DeviceType        T   `json:"devicetype,omitempty"`
	CPE               []T `json:"cpe,omitempty"`
	//RegexString             T   `json:"regex,omitempty"`
}
