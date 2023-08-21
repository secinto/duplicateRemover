package remover

import (
	"github.com/antchfx/jsonquery"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
	"os"
	"strconv"
	"strings"
)

var (
	log           = NewLogger()
	appConfig     Config
	wantedHosts   = []string{"www", "mail", "portal", "webmail", "dashboard", "login", "remote"}
	unwantedHosts = []string{"autodiscover", "sip", "lyncdiscover", "enterpriseenrollment", "enterpriseregistration"}
)

//-------------------------------------------
//			Initialization methods
//-------------------------------------------

func NewRemover(options *Options) (*Remover, error) {
	finder := &Remover{options: options}
	finder.initialize(options.SettingsFile)
	return finder, nil
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
	appConfig.HttpxDomainsFile = strings.Replace(appConfig.HttpxDomainsFile, "{project_name}", p.options.Project, -1)
	appConfig.DpuxFile = strings.Replace(appConfig.DpuxFile, "{project_name}", p.options.Project, -1)
}

func loadConfigFrom(location string) Config {
	var config Config
	var yamlFile []byte
	var err error

	yamlFile, err = os.ReadFile(location)
	if err != nil {
		yamlFile, err = os.ReadFile(defaultSettingsLocation)
		if err != nil {
			log.Fatalf("yamlFile.Get err   #%v ", err)
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	if &config == nil {
		config = Config{
			S2SPath:          "S://",
			HttpxDomainsFile: "http_from.domains.output.json",
			DpuxFile:         "dpux.{project_name}.output.json",
			DpuxIPFile:       "dpux.txt",
		}
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}
	return config
}

//-------------------------------------------
//			Main functions methods
//-------------------------------------------

func (p *Remover) Remove() error {
	if p.options.Project != "" {
		log.Infof("Verifying duplications of project %s", p.options.Project)
		p.CleanDomains()
	} else {
		log.Info("No project specified. Exiting application")
	}
	return nil
}

func (p *Remover) CleanDomains() {
	// Get JSON file
	httpxInputFile := p.options.BaseFolder + "recon/" + appConfig.HttpxDomainsFile
	log.Infof("Using HTTPX domains input %s", httpxInputFile)
	httpxInput := GetDocumentFromFile(httpxInputFile)

	ipsInputFile := p.options.BaseFolder + "recon/" + appConfig.DpuxIPFile
	log.Infof("Using DPUx IP input %s", ipsInputFile)
	ipsInput := ReadTxtFileLines(ipsInputFile)

	dpuxInputFile := p.options.BaseFolder + "recon/" + appConfig.DpuxFile
	log.Infof("Using DPUx input %s", dpuxInputFile)
	dpuxInput := GetDocumentFromFile(dpuxInputFile)

	var cleanedDomains []string
	var cleanedDomainsWithPorts []string

	// Get Hosts from DPUX, since not every host must have HTTP services enabled, they would not be found in

	var nonDuplicateHosts []string

	// Iterate over all hosts and resolve duplicates. Use the IP as selector.
	// All identified IP addresses as resolved from DPUX are used.
	// TODO: If the IP has no HTTPs service listening currently it is not added.
	for _, host := range ipsInput {
		log.Infof("Identifying duplicate hosts for IP %s from HTTP responses", host)
		cleanedHosts := p.filterDuplicates(httpxInput, host)
		if len(cleanedHosts) > 0 {
			for _, duplicate := range cleanedHosts {
				log.Debugf("Adding hostname %s to non duplicates", duplicate.Input)
				nonDuplicateHosts = append(nonDuplicateHosts, duplicate.Input)
			}
		} else {
			dnsEntry := GetSimpleDNSEntryForHost(dpuxInput, host)
			if dnsEntry.Host != "" {
				log.Debugf("Adding hostname %s to non duplicates", dnsEntry.Host)
				nonDuplicateHosts = append(nonDuplicateHosts, dnsEntry.Host)
			}
		}
	}

	for _, host := range nonDuplicateHosts {
		cleanedDomainsWithPorts = AppendIfMissing(cleanedDomainsWithPorts, host)
		if strings.Contains(host, ":") {
			host = strings.Split(host, ":")[0]
		}
		if !checkIfHostStringIsContained(host, unwantedHosts, "") {
			cleanedDomains = AppendIfMissing(cleanedDomains, host)
		} else {
			log.Infof("Not using host %s", host)
		}
	}

	log.Infof("Found %d non duplicate hosts without port", len(cleanedDomains))
	cleanedDomainsString := ConvertStringArrayToString(cleanedDomains, "\n")
	WriteToTextFileInProject(p.options.BaseFolder+"domains_clean.txt", cleanedDomainsString)

	log.Infof("Found %d non duplicate hosts with port", len(cleanedDomainsWithPorts))
	cleanedDomainsWithPortsString := ConvertStringArrayToString(cleanedDomainsWithPorts, "\n")
	WriteToTextFileInProject(p.options.BaseFolder+"domains_clean_with_http_ports.txt", cleanedDomainsWithPortsString)

	log.Info("Created cleaned domains file for project")

}

//-------------------------------------------
//			Helper methods
//-------------------------------------------

func (p *Remover) filterDuplicates(httpxInput *jsonquery.Node, host string) map[string]SimpleHTTPXEntry {
	duplicates := GetSimpleHostEntryForHost(httpxInput, host)
	cleanAfterHash := make(map[string]SimpleHTTPXEntry)
	// Finding duplicates based on the hash values for the same IP.
	for _, duplicate := range duplicates {
		log.Debugf("Checking hostname %s", duplicate.Input)
		if _, ok := cleanAfterHash[duplicate.BodyHash]; !ok {
			// TLD other than the project domain are added to cleanAfterHash. If the project TLD is found
			// it is returned as best match and must be added manually. If another subdomain is found instead
			// of the project domain (not in the list) it is also returned as best match and must be added.
			// If no best match is found the current hostname is added (should only be the case when?)
			bestMatch := getBestDuplicateMatch(duplicates, duplicate.BodyHash, p.options.Project, cleanAfterHash)
			if (bestMatch != SimpleHTTPXEntry{}) {
				cleanAfterHash[duplicate.BodyHash] = bestMatch
			} else {
				cleanAfterHash[duplicate.BodyHash] = duplicate
			}
		}
	}
	// Also find duplicates based on the words and lines from the HTTP response. If they are the same
	// for the same IP it is very likely that the content is the same although some minor thing changed
	// and therefore the hash changed. (Used IP, hostname or some other changes such as generated Javascript)
	// See austria-beteiligungen (hvw-wegraz.at), jaw.or.at for reasons.
	cleanAfterWordsAndLines := make(map[string]SimpleHTTPXEntry)

	for _, duplicate := range cleanAfterHash {
		log.Debugf("Checking hostname %s", duplicate.Input)
		if _, ok := cleanAfterWordsAndLines[strconv.Itoa(duplicate.Words)+"-"+strconv.Itoa(duplicate.Lines)]; !ok {
			possibleDupes := getSimpleEntriesForWordsAndLines(cleanAfterHash, duplicate.Words, duplicate.Lines)
			bestMatch := getBestWordLinesMatch(possibleDupes, p.options.Project, cleanAfterWordsAndLines)
			if (bestMatch != SimpleHTTPXEntry{}) {
				// Use the best match
				cleanAfterWordsAndLines[strconv.Itoa(duplicate.Words)+"-"+strconv.Itoa(duplicate.Lines)] = bestMatch
			} else {
				// If empty, meaning no best match found, use the current one.
				cleanAfterWordsAndLines[strconv.Itoa(duplicate.Words)+"-"+strconv.Itoa(duplicate.Lines)] = duplicate
			}
		}
	}
	// Add the filtered list to nonduplicate ones.
	return cleanAfterWordsAndLines

}

func getBestDuplicateMatch(entries []SimpleHTTPXEntry, bodyHash string, project string, nonDupes map[string]SimpleHTTPXEntry) SimpleHTTPXEntry {
	var match SimpleHTTPXEntry
	var currentBestMatch SimpleHTTPXEntry
	var possibleBestMatch SimpleHTTPXEntry
	for _, entry := range entries {
		if bodyHash == entry.BodyHash {
			tld := ExtractDomainAndTldFromString(entry.Input)
			if tld == entry.Input {
				if tld == project {
					currentBestMatch = entry
					//break
				} else {
					//currentBestMatch = entry
					nonDupes[RandStringRunes(10)] = entry
					log.Debugf("Added non duplicate entry: %s", entry.Input)
				}
			}
			if (possibleBestMatch == SimpleHTTPXEntry{}) {
				if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
					possibleBestMatch = entry
				} else {
					match = entry
				}
			} else {
				match = entry
			}
		}
	}

	if (currentBestMatch != SimpleHTTPXEntry{}) {
		match = currentBestMatch
	} else if (possibleBestMatch != SimpleHTTPXEntry{}) {
		match = possibleBestMatch
	}
	log.Debugf("Found best match for duplicates with hash %s is host %s", bodyHash, match.Input)
	return match
}

func getBestWordLinesMatch(entries []SimpleHTTPXEntry, project string, nonDupes map[string]SimpleHTTPXEntry) SimpleHTTPXEntry {
	var match SimpleHTTPXEntry
	var currentBestMatch SimpleHTTPXEntry
	var possibleBestMatch SimpleHTTPXEntry
	for count, entry := range entries {
		tld := ExtractDomainAndTldFromString(entry.Input)
		log.Debugf("Duplicate entry %d : %s", count, entry.Input)
		if tld == entry.Input {
			if tld == project {
				currentBestMatch = entry
			} else {
				//currentBestMatch = entry
				nonDupes[entry.Input] = entry
				log.Debugf("Added non duplicate entry: %s", entry.Input)
			}
		}
		if (possibleBestMatch == SimpleHTTPXEntry{}) {
			if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
				possibleBestMatch = entry
			} else {
				match = entry
			}
		} else {
			match = entry
		}
	}

	if (currentBestMatch != SimpleHTTPXEntry{}) {
		match = currentBestMatch
	} else if (possibleBestMatch != SimpleHTTPXEntry{}) {
		match = possibleBestMatch
	}
	log.Infof("Found best match host %s", match.Input)
	return match
}

func getSimpleEntriesForWordsAndLines(entries map[string]SimpleHTTPXEntry, words int, lines int) []SimpleHTTPXEntry {
	var filteredEntries []SimpleHTTPXEntry
	for _, entry := range entries {
		if entry.Words == words && entry.Lines == lines {
			filteredEntries = append(filteredEntries, entry)
		}

	}
	return filteredEntries
}

func checkIfHostStringIsContained(host string, hostSlice []string, tld string) bool {
	parts := strings.Split(host, ".")
	if tld != "" {
		tldParts := strings.Split(tld, ".")
		if len(parts) > 0 && (len(parts) == len(tldParts)+1) {
			if slices.Contains(hostSlice, parts[0]) {
				return true
			}
		}
	} else {
		if len(parts) > 0 {
			if slices.Contains(hostSlice, parts[0]) {
				return true
			}
		}
	}

	return false
}
