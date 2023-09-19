package remover

import (
	"encoding/json"
	"github.com/antchfx/jsonquery"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
	"os"
	"reflect"
	"strconv"
	"strings"
)

var (
	log           = NewLogger()
	appConfig     Config
	wantedHosts   = []string{"www", "mail", "portal", "webmail", "dashboard", "login", "remote", "ssh"}
	unwantedHosts = []string{"autodiscover", "sip", "lyncdiscover", "enterpriseenrollment", "enterpriseregistration", "_dmarc", "s1._domainkey"}
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
			DpuxIPFile:       "dpux_clean.txt",
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

	// Get Hosts from DPUX, since not every ipAddress must have HTTP services enabled, they would not be found in

	var nonDuplicateHosts []string
	var duplicateHosts []Duplicates
	var dnsRecords []DNSRecord
	// Iterate over all hosts and resolve duplicates. Use the IP as selector.
	// All identified IP addresses as resolved from DPUX are used.
	for _, ipAddress := range ipsInput {
		log.Infof("Identifying duplicate hosts for IP %s from HTTP responses", ipAddress)
		cleanedHosts, duplicates := p.deduplicateByContent(httpxInput, ipAddress)
		if len(cleanedHosts) > 0 {
			for _, uniqueHost := range cleanedHosts {
				log.Debugf("Adding hostname %s to non duplicates", uniqueHost.Input)
				nonDuplicateHosts = AppendIfMissing(nonDuplicateHosts, uniqueHost.Input)
				host, _ := getHostAndPort(uniqueHost.Input)
				dnsEntry := GetDNSRecordForHostname(dpuxInput, host)
				if dnsEntry.Host != "" {
					dnsRecords = AppendDNSRecordIfMissing(dnsRecords, dnsEntry)
				} else {
					log.Debugf("Found DNS record with empty ipAddress during processing IP %s", ipAddress)
				}
			}
		} else {
			dnsEntry := GetDNSRecordForIPAddress(dpuxInput, ipAddress)
			if dnsEntry.Host != "" {
				log.Debugf("Adding hostname %s to non duplicates for IP %s", dnsEntry.Host, ipAddress)
				nonDuplicateHosts = AppendIfMissing(nonDuplicateHosts, dnsEntry.Host)
				dnsRecords = AppendDNSRecordIfMissing(dnsRecords, dnsEntry)
			} else {
				log.Debugf("Found DNS record with empty ipAddress during processing IP %s", ipAddress)
			}
		}
		for _, duplicateEntry := range duplicates {
			duplicateHosts = AppendDuplicatesIfMissing(duplicateHosts, duplicateEntry)
		}
	}

	var cleanedDomains []string
	var cleanedDomainsWithPorts []string

	for _, hostEntry := range nonDuplicateHosts {
		host, port := getHostAndPort(hostEntry)

		if !checkIfHostStringIsContained(host, unwantedHosts, "") {
			cleanedDomains = AppendIfMissing(cleanedDomains, host)
			if port != "" {
				cleanedDomainsWithPorts = AppendIfMissing(cleanedDomainsWithPorts, host+":"+port)
			} else {
				cleanedDomainsWithPorts = AppendIfMissing(cleanedDomainsWithPorts, host)

			}
		} else {
			log.Infof("Not using ipAddress %s", host)
		}
	}

	log.Infof("Found %d non duplicate hosts without port", len(cleanedDomains))
	cleanedDomainsString := ConvertStringArrayToString(cleanedDomains, "\n")
	WriteToTextFileInProject(p.options.BaseFolder+"domains_clean.txt", cleanedDomainsString)

	log.Infof("Found %d non duplicate hosts with port", len(cleanedDomainsWithPorts))
	cleanedDomainsWithPortsString := ConvertStringArrayToString(cleanedDomainsWithPorts, "\n")
	WriteToTextFileInProject(p.options.BaseFolder+"domains_clean_with_http_ports.txt", cleanedDomainsWithPortsString)

	data, _ := json.MarshalIndent(duplicateHosts, "", " ")
	WriteToTextFileInProject(p.options.BaseFolder+"findings/duplicates.json", string(data))

	data, _ = json.MarshalIndent(dnsRecords, "", " ")
	WriteToTextFileInProject(p.options.BaseFolder+"findings/dns_clean.json", string(data))

	log.Info("Created cleaned domains file for project")

}

//-------------------------------------------
//			Helper methods
//-------------------------------------------

func (p *Remover) deduplicateByContent(httpxInput *jsonquery.Node, ipaddress string) ([]SimpleHTTPXEntry, map[string]Duplicates) {
	hostsOnSameIP := GetHTTPXEntryForIPAddress(httpxInput, ipaddress)
	cleanAfterHash := make(map[string]SimpleHTTPXEntry)
	// TLDs are always used, even if they are duplicates
	tlds := make(map[string]SimpleHTTPXEntry)
	duplicates := make(map[string]Duplicates)
	cleanAfterWordsAndLines := make(map[string]SimpleHTTPXEntry)
	if len(hostsOnSameIP) > 0 {
		// Finding duplicates based on the hash values for the same IP.
		log.Debugf("Checking duplicates for IP %s", ipaddress)
		for _, hostEntry := range hostsOnSameIP {
			log.Debugf("Checking hostname %s", hostEntry.Input)
			if _, ok := cleanAfterHash[hostEntry.BodyHash]; !ok {
				// TLD other than the project domain are added to tlds. If the project TLD is found
				// it is returned as best match and must be added manually. If another subdomain is found instead
				// of the project domain (not in the list) it is also returned as best match and must be added.
				// If no best match is found the current hostname is added (should only be the case when?)
				possibleDupes := getSimpleEntriesForBodyHash(hostsOnSameIP, hostEntry.BodyHash)
				if len(possibleDupes) > 1 {
					bestMatch := getBestDuplicateMatch(possibleDupes, p.options.Project, tlds)
					if (bestMatch != SimpleHTTPXEntry{}) {
						cleanAfterHash[hostEntry.BodyHash] = bestMatch
					} else {
						cleanAfterHash[hostEntry.BodyHash] = hostEntry
					}
					// Create the base entry for the duplicates. All duplicates of the bodyHash are associated with this entry
					duplicate := getDuplicate(cleanAfterHash[hostEntry.BodyHash])
					if duplicate.Hostname != hostEntry.Input {
						duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, hostEntry.Input)
					}
					duplicates[hostEntry.BodyHash] = duplicate
				} else {
					//Only one exists, use it
					cleanAfterHash[hostEntry.BodyHash] = hostEntry
				}
			} else {
				//All other are duplicates
				duplicate := duplicates[hostEntry.BodyHash]
				if reflect.DeepEqual(Duplicates{}, duplicate) {
					duplicate = getDuplicate(hostEntry)
				}
				if duplicate.Hostname != hostEntry.Input {
					duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, hostEntry.Input)
				}
				duplicates[hostEntry.BodyHash] = duplicate
			}
		}
		// Also find duplicates based on the words and lines from the HTTP response. If they are the same
		// for the same IP it is very likely that the content is the same although some minor thing changed
		// and therefore the hash changed. (Used IP, hostname or some other changes such as generated Javascript)
		// See austria-beteiligungen (hvw-wegraz.at), jaw.or.at for reasons.
		for _, hostEntry := range cleanAfterHash {
			key := strconv.Itoa(hostEntry.Words) + "-" + strconv.Itoa(hostEntry.Lines)
			if len(cleanAfterHash) > 1 {
				log.Debugf("Checking hostname %s", hostEntry.Input)
				if _, ok := cleanAfterWordsAndLines[key]; !ok {
					possibleDupes := getSimpleEntriesForWordsAndLines(cleanAfterHash, hostEntry.Words, hostEntry.Lines)
					if len(possibleDupes) > 1 {
						bestMatch := getBestDuplicateMatch(possibleDupes, p.options.Project, tlds)
						if (bestMatch != SimpleHTTPXEntry{}) {
							// Use the best match
							cleanAfterWordsAndLines[key] = bestMatch
						} else {
							// If empty, meaning no best match found, use the current one.
							cleanAfterWordsAndLines[key] = hostEntry
						}
						// Create the base entry for the duplicates. All duplicates of the words and lines are associated with this entry
						duplicate := getDuplicate(cleanAfterWordsAndLines[key])
						//If a duplicate for the body hash already exists, inline it to the new duplicates entry
						if !reflect.DeepEqual(Duplicates{}, duplicates[duplicate.BodyHash]) {
							if duplicate.Hostname != duplicates[duplicate.BodyHash].Hostname {
								duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, duplicates[duplicate.BodyHash].Hostname)
							}
							duplicate.DuplicateHosts = AppendSliceIfMissingExcept(duplicate.DuplicateHosts, duplicates[duplicate.BodyHash].DuplicateHosts, duplicate.Hostname)
							delete(duplicates, duplicate.BodyHash)
						}
						if duplicate.Hostname != hostEntry.Input {
							duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, hostEntry.Input)
							if !reflect.DeepEqual(Duplicates{}, duplicates[hostEntry.BodyHash]) {
								duplicate.DuplicateHosts = AppendSliceIfMissingExcept(duplicate.DuplicateHosts, duplicates[hostEntry.BodyHash].DuplicateHosts, duplicate.Hostname)
								delete(duplicates, hostEntry.BodyHash)
							}
						}
						duplicates[key] = duplicate
					} else {
						//Only one entry exists, use it.
						cleanAfterWordsAndLines[key] = hostEntry
						// Create the base entry for the duplicates. All duplicates of the words and lines are associated with this entry
						duplicate := getDuplicate(cleanAfterWordsAndLines[key])
						//If a duplicate for the body hash already exists, inline it to the new duplicates entry
						if !reflect.DeepEqual(Duplicates{}, duplicates[duplicate.BodyHash]) {
							if duplicate.Hostname != duplicates[duplicate.BodyHash].Hostname {
								duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, duplicates[duplicate.BodyHash].Hostname)
							}
							duplicate.DuplicateHosts = AppendSliceIfMissingExcept(duplicate.DuplicateHosts, duplicates[duplicate.BodyHash].DuplicateHosts, duplicate.Hostname)
							delete(duplicates, hostEntry.BodyHash)
						}
						duplicates[key] = duplicate
					}
				} else {
					// All other are duplicates
					duplicate := duplicates[key]
					//If empty create new one
					if reflect.DeepEqual(Duplicates{}, duplicate) {
						duplicate = getDuplicate(hostEntry)
					}
					if duplicate.Hostname != hostEntry.Input {
						duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, hostEntry.Input)
					}
					//If a duplicate for the body hash already exists, inline it to the new duplicates entry
					if !reflect.DeepEqual(Duplicates{}, duplicates[hostEntry.BodyHash]) {
						if duplicate.Hostname != duplicates[duplicate.BodyHash].Hostname {
							duplicate.DuplicateHosts = AppendIfMissing(duplicate.DuplicateHosts, duplicates[hostEntry.BodyHash].Hostname)
						}
						duplicate.DuplicateHosts = AppendSliceIfMissingExcept(duplicate.DuplicateHosts, duplicates[hostEntry.BodyHash].DuplicateHosts, duplicate.Hostname)
						delete(duplicates, hostEntry.BodyHash)
					}
					duplicates[key] = duplicate
				}
			} else {
				cleanAfterWordsAndLines[key] = hostEntry
			}
		}
	}
	// Add the filtered list to nonduplicate ones.
	var combined []SimpleHTTPXEntry
	for _, entry := range cleanAfterWordsAndLines {
		combined = append(combined, entry)
		host, _ := getHostAndPort(entry.Input)
		if len(tlds) > 0 {
			delete(tlds, host)
		}
	}
	found := false
	for _, tld := range tlds {
		for _, entry := range combined {
			if tld.Input == entry.Input {
				found = true
				continue
			}
		}
		if found == false {
			combined = append(combined, tld)
		}
		found = false
	}
	return combined, duplicates

}

/*
Finds the best match for different hostnames which result in the same hash value for the response, thus having the same
content. The TLD of the project or in general is a TLD it is the preferred best duplicate match. Otherwise, the first
matching from a list of preferred ones is used. If none has matched the last one which is checked is used.
Currently it is not differentiated between ports.
Project: example.com
Duplicates: example.com (1), example.at (2), test.example.com, www.example.com (3), sub.example.com (4)
*/
func getBestDuplicateMatch(entries []SimpleHTTPXEntry, project string, tlds map[string]SimpleHTTPXEntry) SimpleHTTPXEntry {
	var match SimpleHTTPXEntry
	var currentBestMatch SimpleHTTPXEntry
	var possibleBestMatch SimpleHTTPXEntry
	var host string
	var port string
	for _, entry := range entries {
		host, port = getHostAndPort(entry.Input)
		tld := ExtractDomainAndTldFromString(host)
		// If entry is a top level domain we either use it as current best match, if it is the same as the project.
		// If not we use it as possible best match if it is an entry with port 443. If not we use it as general
		if tld == host {
			if tld == project {
				if (currentBestMatch != SimpleHTTPXEntry{}) {
					cbmHost, _ := getHostAndPort(currentBestMatch.Input)
					if _, ok := tlds[cbmHost]; !ok {
						tlds[cbmHost] = currentBestMatch
					}
				}
				if port == "443" {
					currentBestMatch = entry
				} else if (currentBestMatch == SimpleHTTPXEntry{}) {
					currentBestMatch = entry
				}

			} else {
				if port == "443" && (currentBestMatch == SimpleHTTPXEntry{}) {
					currentBestMatch = entry
				} else {
					if _, ok := tlds[host]; !ok {
						tlds[host] = entry
					}
					if (possibleBestMatch == SimpleHTTPXEntry{}) {
						possibleBestMatch = entry
					}
				}
				log.Debugf("Added non duplicate entry: %s", entry.Input)
			}
		} else if (match == SimpleHTTPXEntry{}) {
			match = entry
		} else if (match != SimpleHTTPXEntry{}) {
			if checkIfHostStringIsContained(entry.Input, wantedHosts, tld) {
				match = entry
			}
			if subDomainCount(match.Input) > subDomainCount(entry.Input) {
				match = entry
			}
		}
	}

	if (currentBestMatch != SimpleHTTPXEntry{}) {
		match = currentBestMatch
	} else if (possibleBestMatch != SimpleHTTPXEntry{}) {
		match = possibleBestMatch
	}
	// Remove the match from TLDs if it exists
	host, port = getHostAndPort(match.Input)
	delete(tlds, host)

	log.Debugf("Found best match for duplicates with hash %s or words %d and lines %d is host %s", match.BodyHash, match.Words, match.Lines, match.Input)
	return match
}

func getSimpleEntriesForBodyHash(entries []SimpleHTTPXEntry, bodyHash string) []SimpleHTTPXEntry {
	var filteredEntries []SimpleHTTPXEntry
	for _, entry := range entries {
		if bodyHash == entry.BodyHash {
			filteredEntries = append(filteredEntries, entry)
		}
	}
	return filteredEntries
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
