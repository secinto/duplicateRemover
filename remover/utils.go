package remover

import (
	"bufio"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

var (
	client = http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}
)

func CreateDirectoryIfNotExists(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0o770)
		if err != nil {
			return err
		}
	}
	return nil
}

func CreateOutputFromInput(input string) string {

	output := strings.ReplaceAll(input, ".json", ".struct.json")
	return output
}

func WriteToTextFileInProject(filename string, data string) {
	writeFile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	dataWriter := bufio.NewWriter(writeFile)

	if err != nil {
		log.Error(err)
	}
	dataWriter.WriteString(data)
	dataWriter.Flush()
	writeFile.Close()
}

func ConvertStringArrayToString(stringArray []string, separator string) string {
	sort.Strings(stringArray)
	justString := strings.Join(stringArray, separator)
	return justString
}

func CheckIfArrayContainsString(stringArray []string, stringToCheck string) bool {
	for _, element := range stringArray {
		if strings.Contains(element, stringToCheck) {
			return true
		}
	}
	return false
}

func ExtractDomainAndTldFromString(str string) string {

	var domainTld string

	parts := strings.Split(str, ".")

	if len(parts) < 2 {
		log.Error("Invalid domain " + str)
	} else {
		domainTld = parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	log.Info(domainTld)
	return domainTld

}

func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func AppendIfMissing(slice []string, key string) []string {
	for _, element := range slice {
		if element == key {
			return slice
		}
	}
	return append(slice, key)
}

func ExistsInArray(slice []string, key string) bool {
	for _, element := range slice {
		if element == key {
			return true
		}
	}
	return false
}

func BestHostMatch(check string, existing string) {
	if strings.Contains(check, "www.") || strings.Contains(check, "main.") || strings.Contains(check, ".com") || strings.Contains(check, "t") {

	}
}

func GetHost(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		return str
	}
	return u.Scheme + "://" + u.Host
}

func ConvertJSONtoJSONL(input string) string {

	var data []byte
	data = append(data, '[')

	lines := strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n")

	isFirst := true
	for _, line := range lines {
		if !isFirst && strings.TrimSpace(line) != "" {
			data = append(data, ',')
			data = append(data, '\n')
		}
		if strings.TrimSpace(line) != "" {
			data = append(data, line...)
		}
		isFirst = false
	}
	data = append(data, ']')
	return string(data)
}

func MergeIpsAndDomains(inputFile1 string, inputFile2 string, mergedFile string) {
	// Read the contents of inputFile1 and inputFile2
	content1, err := ioutil.ReadFile(inputFile1)
	content2, err2 := ioutil.ReadFile(inputFile2)

	var mergedContent []byte

	if err == nil && err2 != nil {
		mergedContent = content1
	} else if err != nil && err2 == nil {
		mergedContent = content2
	} else if err != nil && err2 != nil {
		// Combine the contents of inputFile1 and inputFile2
		mergedContent = append(content1, content2...)
		log.Println("Ip and Domains file merged successfully")
	} else {
		log.Fatal("Problem occured, cannot read: " + inputFile1 + " and " + inputFile2)
	}

	// Write the combined content to a new file
	err = ioutil.WriteFile(mergedFile, mergedContent, 0644)
	if err != nil {
		log.Fatalln("Error writing merged file:", err)
	}

}

func CheckIfFileExists(path string, stopRunning bool) bool {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		if stopRunning == true {
			log.Fatal("File " + path + " does not exist!")
			return false
		} else {
			log.Info("File " + path + " does not exist!")
			return false
		}
	}
	if err != nil {
		log.Fatal("Error checking file:", err)
		return false
	}

	return true
}

func ReadTxtFileLines(path string) []string {
	var lines []string
	f, err := os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		log.Fatalf("open file error: %v", err)
		return []string{}
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")
		if err != nil {
			if err == io.EOF {
				lines = append(lines, line)
				break
			}

			log.Fatalf("read file line error: %v", err)
			return []string{}
		}
		if len(line) > 0 {
			lines = append(lines, line) // GET the line string
		}

	}

	return lines
}

func CheckRequirements(files []string, stopRunning bool) bool {
	for _, file := range files {
		if CheckIfFileExists(file, stopRunning) == false {
			return false
		}
	}
	return true
}

func GetFileName(url string, extension string, funcName string) string {
	fileName := strings.ReplaceAll(url, "//", "")
	fileName = strings.ReplaceAll(fileName, ".", "_")
	fileName = strings.ReplaceAll(fileName, ":", "_")

	if len(funcName) > 0 {
		fileName = funcName + "_" + fileName
	}

	return fileName + extension
}

func getDomainFromString(str string) string {
	var domain string

	parts := strings.Split(str, ".")

	if len(parts) < 2 {
		log.Error("Invalid domain " + str)
	} else {
		domain = parts[0]
	}
	log.Info(domain)
	return domain
}
