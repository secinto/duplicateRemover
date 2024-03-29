package remover

const VERSION = "0.2.3"

type Config struct {
	S2SPath          string `yaml:"s2s_path,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
	DpuxFile         string `yaml:"dpux,omitempty"`
	DpuxIPFile       string `yaml:"dpux_ip,omitempty"`
}

type Remover struct {
	options *Options
}

type SimpleHTTPXEntry struct {
	Host          string
	BodyHash      string
	Status        int
	ContentLength int
	Lines         int
	Words         int
	Input         string
	URL           string
	Title         string
}

type DNSRecord struct {
	Host          string   `yaml:"host"`
	IPv4Addresses []string `yaml:"ipv4"`
	IPv6Addresses []string `yaml:"ipv6,omitempty"`
	WhoisInfo     string   `yaml:"whois,omitempty"`
}

type Duplicates struct {
	Hostname       string
	IP             string
	URL            string
	BodyHash       string
	ContentLength  int
	Lines          int
	Words          int
	Status         int
	DuplicateHosts []string
}

func getDuplicate(entry SimpleHTTPXEntry) Duplicates {
	duplicate := Duplicates{
		Hostname:       entry.Input,
		IP:             entry.Host,
		BodyHash:       entry.BodyHash,
		ContentLength:  entry.ContentLength,
		Lines:          entry.Lines,
		Words:          entry.Words,
		URL:            entry.URL,
		Status:         entry.Status,
		DuplicateHosts: []string{},
	}
	return duplicate
}
