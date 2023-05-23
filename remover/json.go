package remover

import (
	"github.com/antchfx/jsonquery"
	"os"
	"strconv"
	"strings"
)

func GetDocumentFromFile(filename string) *jsonquery.Node {
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalf("Reading JSON input file failed: %s %s", err.Error(), filename)
	}
	jsonlString := ConvertJSONtoJSONL(string(data))
	jsonReader := strings.NewReader(jsonlString)
	input, err := jsonquery.Parse(jsonReader)
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
			entry := GetEntry(entryValues)
			entries = append(entries, entry)
		}
	}

	return entries
}

func GetSimpleEntryForBodyHashAndHost(document *jsonquery.Node, host string, bodyHash string) []SimpleHTTPXEntry {
	var entries []SimpleHTTPXEntry
	entriesForHost, error := jsonquery.QueryAll(document, "//*[(host='"+host+"') and (body_sha256='"+bodyHash+"')]")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}
	for _, hostEntry := range entriesForHost {
		if entryValues, ok := hostEntry.Value().(map[string]interface{}); ok {
			entry := GetEntry(entryValues)
			entries = append(entries, entry)
		}
	}

	return entries
}

func GetSimpleEntryForWordsLinesAndHost(document *jsonquery.Node, host string, words int, lines int) []SimpleHTTPXEntry {
	var entries []SimpleHTTPXEntry
	entriesForHost, error := jsonquery.QueryAll(document, "//*[(host='"+host+"') and (words='"+strconv.Itoa(words)+"') and (lines='"+strconv.Itoa(lines)+"') ]")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}
	for _, hostEntry := range entriesForHost {
		if entryValues, ok := hostEntry.Value().(map[string]interface{}); ok {
			entry := GetEntry(entryValues)
			entries = append(entries, entry)
		}
	}

	return entries
}

func GetEntry(entryValues map[string]interface{}) SimpleHTTPXEntry {
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

func GetHostCounts(document *jsonquery.Node) map[string]int {
	entries, error := jsonquery.QueryAll(document, "//a")
	if error != nil {
		log.Errorf("Querying JSON error   #%v ", error)
	}

	hosts := make(map[string]int)

	for _, entry := range entries {
		if hostValues, ok := entry.Value().([]interface{}); ok {
			for _, host := range hostValues {
				if hostValue, ok := host.(string); ok {

					value, exists := hosts[hostValue]

					if exists {
						hosts[hostValue] = value + 1
					} else {
						hosts[hostValue] = 1
					}
				}
			}
		}
	}
	return hosts
}
