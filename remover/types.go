package remover

const VERSION = "0.1"

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
	Host           string
	BodyHash       string
	Status         int
	ContentLength  int
	Lines          int
	Words          int
	Input          string
	URL            string
	Title          string
	UseIfDuplicate bool `default:false`
}

type SimpleDNSXEntry struct {
	Host          string   `yaml:"host"`
	IPv4Addresses []string `yaml:"ipv4"`
	IPv6Addresses []string `yaml:"ipv6,omitempty"`
	WhoisInfo     string   `yaml:"whois,omitempty"`
}

type Duplicate struct {
	Status        int
	ContentLength int
	Lines         int
	Words         int
}
