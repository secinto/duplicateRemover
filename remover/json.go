package remover

import (
	"github.com/antchfx/jsonquery"
	"os"
)

func GetDocumentFromFile(filename string) *jsonquery.Node {
	// Get JSON file
	f, err := os.Open(filename)
	// Parse JSON file
	input, err := jsonquery.Parse(f)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}
	return input
}

func GetSimpleEntryForHost(document *jsonquery.Node, host string) []SimpleHTTPXEntry {
	var entries []SimpleHTTPXEntry
	entriesForHost, error := jsonquery.QueryAll(document, "//*[host='"+host+"']")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}
	for _, hostEntry := range entriesForHost {
		if entryValues, ok := hostEntry.Value().(map[string]interface{}); ok {
			var entry SimpleHTTPXEntry
			if hashValues, ok := entryValues["hash"].(map[string]interface{}); ok {
				if bodySha256, ok := hashValues["body_sha256"].(string); ok {
					entry.BodyHash = bodySha256
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
			if input, ok := entryValues["input"].(string); ok {
				entry.Input = input
			}
			if url, ok := entryValues["url"].(string); ok {
				entry.URL = url
			}

			entries = append(entries, entry)
		}
	}

	return entries
}

func GetHostCounts(document *jsonquery.Node) map[string]int {
	entries, error := jsonquery.QueryAll(document, "//host")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	hosts := make(map[string]int)

	for _, entry := range entries {
		if host, ok := entry.Value().(string); ok {
			value, exists := hosts[host]
			if exists {
				hosts[host] = value + 1
			} else {
				hosts[host] = 1
			}
		}
	}
	return hosts
}
