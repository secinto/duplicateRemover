package remover

import (
	"github.com/antchfx/jsonquery"
	"os"
	"strings"
)

func GetDocumentFromFile(filename string) *jsonquery.Node {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}
	jsonlString := ConvertJSONLtoJSON(string(data))
	jsonReader := strings.NewReader(jsonlString)
	input, err := jsonquery.Parse(jsonReader)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}

	return input
}

func GetSimpleHostEntryForHost(document *jsonquery.Node, host string) []SimpleHTTPXEntry {
	var entries []SimpleHTTPXEntry
	entriesForHost, error := jsonquery.QueryAll(document, "//*[host='"+host+"']")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}
	for _, hostEntry := range entriesForHost {
		if entryValues, ok := hostEntry.Value().(map[string]interface{}); ok {
			entry := CreateSimpleHostEntryFromHTTPX(entryValues)
			entries = append(entries, entry)
		}
	}

	return entries
}

func GetSimpleDNSEntryForHost(document *jsonquery.Node, host string) SimpleDNSXEntry {
	entriesForHost, error := jsonquery.Query(document, "//*/a[contains(.,'"+host+"')]")

	entry := SimpleDNSXEntry{}

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	} else {
		if entriesForHost != nil && entriesForHost.Parent != nil {
			log.Debugf("Entries for host %s are # %d", host, entriesForHost.Type)
			entry = CreateSimpleDNSEntryFromDPUX(entriesForHost.Parent)
		} else {
			log.Errorf("Provided entries for host %s doesn't have a parent", host)
		}
	}
	return entry
}

func CreateSimpleHostEntryFromHTTPX(entryValues map[string]interface{}) SimpleHTTPXEntry {
	var entry SimpleHTTPXEntry
	if hashValues, ok := entryValues["hash"].(map[string]interface{}); ok {
		if bodyMmh3, ok := hashValues["body_mmh3"].(string); ok {
			entry.BodyHash = bodyMmh3
		}
	}

	if contentLength, ok := entryValues["content_length"].(float64); ok {
		entry.ContentLength = int(contentLength)
	}
	if statusCode, ok := entryValues["status_code"].(float64); ok {
		entry.Status = int(statusCode)
	}
	if lines, ok := entryValues["lines"].(float64); ok {
		entry.Lines = int(lines)
	}
	if words, ok := entryValues["words"].(float64); ok {
		entry.Words = int(words)
	}
	if host, ok := entryValues["host"].(string); ok {
		entry.Host = host
	}
	if title, ok := entryValues["title"].(string); ok {
		entry.Title = title
	}
	if input, ok := entryValues["input"].(string); ok {
		entry.Input = input
	}
	if url, ok := entryValues["url"].(string); ok {
		entry.URL = url
	}
	return entry
}

func CreateSimpleDNSEntryFromDPUX(record *jsonquery.Node) SimpleDNSXEntry {
	var entry SimpleDNSXEntry
	if entryValues, ok := record.Value().(map[string]interface{}); ok {

		var ip4Addresses []string
		var ip6Addresses []string
		host := entryValues["host"].(string)

		if entries, ok := entryValues["a"].([]interface{}); ok {
			for _, address := range entries {
				if _, ok := address.(string); ok {
					ip4Addresses = append(ip4Addresses, address.(string))
				}
			}
		} else if entry, ok := entryValues["a"].(string); ok {
			ip4Addresses = append(ip4Addresses, entry)
		}

		if entries, ok := entryValues["aaaa"].([]interface{}); ok {
			for _, address := range entries {
				if _, ok := address.(string); ok {
					ip6Addresses = append(ip6Addresses, address.(string))
				}
			}
		} else if entry, ok := entryValues["aaaa"].(string); ok {
			ip6Addresses = append(ip6Addresses, entry)
		}

		entry = SimpleDNSXEntry{
			Host:          host,
			IPv4Addresses: ip4Addresses,
			IPv6Addresses: ip6Addresses,
		}
	} else {
		entry = SimpleDNSXEntry{}
	}
	return entry
}

func GetHostCounts(document *jsonquery.Node) map[string]int {
	entries, error := jsonquery.QueryAll(document, "//host")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	hosts := make(map[string]int)

	for _, entry := range entries {
		if hostValue, ok := entry.Value().(string); ok {

			if value, exists := hosts[hostValue]; exists {
				hosts[hostValue] = value + 1
			} else {
				hosts[hostValue] = 1
			}
		}
	}
	return hosts
}

func GetAllRecordsForKey(document *jsonquery.Node, key string) []*jsonquery.Node {
	return getAllNodesForKey(document, key)
}

func getAllNodesForKey(document *jsonquery.Node, key string) []*jsonquery.Node {
	entries, error := jsonquery.QueryAll(document, "//*["+key+"]")

	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	return entries
}
