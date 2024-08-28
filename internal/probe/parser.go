package probe

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Probe struct {
	Golden         bool   `json:"-"`
	Name           string `json:"ProbeName,omitempty"`
	Data           string `json:"-"`
	TransportProto string `json:"-"`

	Ports    string `json:"-"`
	SSLPorts string `json:"-"`
	Fallback string `json:"-"`

	TotalWaitMS  int                 `json:"-"`
	TCPWrappedMS int                 `json:"-"`
	Rarity       int                 `json:"-"`
	HexFormat    bool                `json:"-"`
	Services     map[string]struct{} `json:"-"`
}

type Match struct {
	IsSoft bool

	Service     string
	Pattern     string
	VersionInfo string

	PatternCompiled *regexp.Regexp
}
type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

func (p *Probe) getDirectiveSyntax(data string) (Directive, error) {
	directive := Directive{}

	if strings.Count(data, " ") <= 0 {
		return directive, fmt.Errorf("nmap-service-probes - error directive format")
	}
	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	//blankSpace := data[blankIndex: blankIndex+1]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	return directive, nil
}

func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
}

func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
}

func (p *Probe) parseTotalWaitMS(data string) {
	p.TotalWaitMS, _ = strconv.Atoi(string(data[len("totalwaitms")+1:]))
}

func (p *Probe) parseTCPWrappedMS(data string) {
	p.TCPWrappedMS, _ = strconv.Atoi(string(data[len("tcpwrappedms")+1:]))
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(string(data[len("rarity")+1:]))
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func (p *Probe) FromString(data string) error {
	var err error

	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	probeStr := lines[0]

	err = p.parseProbeInfo(probeStr)
	if err != nil {
		return err
	}

	p.Services = make(map[string]struct{})
	for _, line := range lines {
		// matches and softmatches is not interested to us becouse we will use product matcher
		// just parse probes which we will use for sending
		switch {
		case strings.HasPrefix(line, "ports "):
			p.parsePorts(line)
		case strings.HasPrefix(line, "sslports "):
			p.parseSSLPorts(line)
		case strings.HasPrefix(line, "totalwaitms "):
			p.parseTotalWaitMS(line)
		case strings.HasPrefix(line, "tcpwrappedms "):
			p.parseTCPWrappedMS(line)
		case strings.HasPrefix(line, "rarity "):
			p.parseRarity(line)
		case strings.HasPrefix(line, "fallback "):
			p.parseFallback(line)
		case strings.HasPrefix(line, "match "):
			p.parseServiceName(line)
		}
	}
	return err
}

func (p *Probe) parseServiceName(fullMatch string) {
	matchProto := strings.SplitN(fullMatch, " m|", 2)
	if len(matchProto) < 2 || len(matchProto[0]) < 6 {
		return
	}
	if _, ok := p.Services[matchProto[0][6:]]; !ok {
		p.Services[matchProto[0][6:]] = struct{}{}
	}
}

func (p *Probe) parseProbeInfo(probeStr string) error {
	proto := probeStr[:4]
	other := probeStr[4:]

	if !(proto == "TCP " || proto == "UDP ") {
		return fmt.Errorf("line %s is bad nmap-service-probes - invalid transport proto", probeStr)
	}
	if len(other) == 0 {
		return fmt.Errorf("line %s is bad nmap-service-probes - bad probe name", probeStr)
	}

	directive, err := p.getDirectiveSyntax(other)
	if err != nil {
		return err
	}

	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.TransportProto = strings.ToLower(strings.TrimSpace(proto))

	return nil
}

func (p *Probe) ContainsPort(testPort int) bool {
	ports := strings.Split(p.Ports, ",")

	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == cmpPort {
			return true
		}
	}
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == cmpPort {
					return true
				}
			}
		}
	}
	return false
}

func (p *Probe) ContainsSSLPort(testPort int) bool {
	ports := strings.Split(p.SSLPorts, ",")

	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == cmpPort {
			return true
		}
	}
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == cmpPort {
					return true
				}
			}
		}
	}
	return false
}

type ProbesRarity []Probe

func (ps ProbesRarity) Len() int {
	return len(ps)
}

func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}
