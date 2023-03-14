package remover

import (
	"gopkg.in/yaml.v3"
	"os"
	"sort"
	"strings"
)

var (
	log       = NewLogger()
	appConfig Config
)

const VERSION = "0.1"

type Config struct {
	S2SPath          string `yaml:"s2s_path,omitempty"`
	HttpxIpFile      string `yaml:"httpx_ips,omitempty"`
	HttpxDomainsFile string `yaml:"httpx_domains,omitempty"`
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
	UseIfDuplicate bool `default:false`
}

type Duplicate struct {
	Status        int
	ContentLength int
	Lines         int
	Words         int
}

func NewRemover(options *Options) (*Remover, error) {
	finder := &Remover{options: options}
	finder.initialize(options.ConfigFile)
	return finder, nil
}

func (p *Remover) Remove() error {
	if p.options.Project != "" {
		log.Infof("Getting findings from domains of project %s", p.options.Project)
		p.CleanDomains()
	} else {
		log.Info("No project specified. Exiting application")
	}
	return nil
}

func (p *Remover) initialize(configLocation string) {
	appConfig = loadConfigFrom(configLocation)
	if !strings.HasSuffix(appConfig.S2SPath, "/") {
		appConfig.S2SPath = appConfig.S2SPath + "/"
	}
	p.options.BaseFolder = appConfig.S2SPath + p.options.Project
	if !strings.HasSuffix(p.options.BaseFolder, "/") {
		p.options.BaseFolder = p.options.BaseFolder + "/"
	}
	appConfig.HttpxIpFile = strings.Replace(appConfig.HttpxIpFile, "{project_name}", p.options.Project, -1)
	appConfig.HttpxDomainsFile = strings.Replace(appConfig.HttpxDomainsFile, "{project_name}", p.options.Project, -1)
}

func loadConfigFrom(location string) Config {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		path, err := os.Getwd()
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}

		yamlFile, err = os.ReadFile(path + "\\config.yaml")
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return config
}

func (p *Remover) CleanDomains() {
	// Get JSON file
	//jsonFile := GetDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.HttpxDomainsFile)

	input := GetDocumentFromFile(p.options.BaseFolder + "recon/" + appConfig.HttpxDomainsFile)
	var cleanedDomains []string

	// Get IPs and amount of entries for that IP
	hosts := GetHostCounts(input)

	// Create an array with all IPs
	keys := make([]string, 0, len(hosts))
	for key := range hosts {
		keys = append(keys, key)
	}

	// Sort the IPs array based on the amount of entries descending.
	sort.SliceStable(keys, func(i, j int) bool {
		return hosts[keys[i]] > hosts[keys[j]]
	})

	nonDuplicateHosts := make(map[string]string)
	//var duplateHosts []data.Duplicate
	// Iterate over all hosts and resolve duplicates if more than 10 entries exist
	for _, host := range keys {
		if hosts[host] > 0 {
			duplicates := GetSimpleEntryForHost(input, host)
			for _, duplicate := range duplicates {
				if _, ok := nonDuplicateHosts[duplicate.BodyHash]; !ok {
					if len(duplicate.Input) > 0 {
						nonDuplicateHosts[duplicate.BodyHash] = duplicate.Input
						//log.Debugf("Using hostname input %s for hash %s", duplicate.Input, duplicate.BodyHash)
					}
				}
			}
		}
	}

	for _, host := range nonDuplicateHosts {

		cleanedDomains = AppendIfMissing(cleanedDomains, host)
	}

	cleanedDomainsString := ConvertStringArrayToString(cleanedDomains, "\n")
	WriteToTextFileInProject(p.options.BaseFolder+"domains_clean.txt", cleanedDomainsString)
}
