package dialer

import "strconv"

type Target struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	SecureUse bool   `json:"ssl/tls"`
}

func (t Target) GetAddress() string {
	if t.Port == 0 {
		return t.IP
	}
	return t.IP + ":" + strconv.Itoa(t.Port)
}
