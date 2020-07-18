package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"
)

// DomainRegex - Regex to identify the dommain
const DomainRegex = "(?i)\\.[a-zA-Z0-9\\-]{2,6}$"

// Format for an Example YAML signature files
type signFileStruct struct {
	ID     string     `yaml:"id"`
	Checks []sigCheck `yaml:"checks"`
}

// Define a separate struct for checks
type sigCheck struct {
	Type   string   `yaml:"type"`
	URL    []string `yaml:"url"`
	Search []string `yaml:"search"`
	Notes  string   `yaml:"notes"`
}

// SIGFILEEXT - Extensions for YAML files
var SIGFILEEXT []string = []string{".yml", ".yaml"}

// Find takes a slice and looks for an element in it. If found it will
// return it's key, otherwise it will return -1 and a bool of false.
func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

// Find files that have the relevant extensions. By default, YAML is used.
func findSigFiles(filesToParse []string) []string {

	var sigFiles []string

	for _, fileToCheck := range filesToParse {
		for _, ext := range SIGFILEEXT {
			isSigFile := strings.Index(fileToCheck, ext)
			if isSigFile != -1 {
				sigFiles = append(sigFiles, fileToCheck)
				break
			}
		}
	}
	return sigFiles
}

// Parse the signature file given the struct and return the contents of YAML
// Signature file
func parseSigFile(sigFile string) signFileStruct {
	var sigFileContent signFileStruct
	yamlFile, err := ioutil.ReadFile(sigFile)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &sigFileContent)
	if err != nil {
		fmt.Printf("[-] Unmarshal: %v\n", err)
		log.Fatalf("[-] Unmarshal: %v\n", err)
	}

	return sigFileContent
}

// Function is used to identify whether specific line is domain OR company, via regex
func domainOrCompany(asset string) string {
	assetType := ""
	found, _ := regexp.MatchString(DomainRegex, asset)
	if found {
		assetType = "domain"
	} else {
		assetType = "company"
	}
	return assetType
}

// Function to open URL in a browser
// Taken from: https://gist.github.com/hyg/9c4afcd91fe24316cbf0
func openbrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func subParams(baseStr string, domain string, company string) string {
	baseStr = strings.ReplaceAll(baseStr, "{domain}", domain)
	baseStr = strings.ReplaceAll(baseStr, "{hostname}", domain)
	baseStr = strings.ReplaceAll(baseStr, "{company}", company)
	return baseStr
}

// Perform check e.g. open search in Google browser, run shodan search
func performCheck(id string, check sigCheck, domain string, company string) {
	notes := check.Notes
	checkType := check.Type
	urls := check.URL
	searches := check.Search

	if checkType == "" || checkType == "browser" || checkType == "browse" {
		if urls != nil {
			for _, url := range urls {
				suburl := subParams(url, domain, company)
				openbrowser(suburl)
			}
		}
	} else if checkType == "google" {
		if searches != nil {
			for _, search := range searches {
				subsearch := subParams(search, domain, company)
				if subsearch != "" {
					url := "https://www.google.com/search?q={subsearch}"
					url = strings.ReplaceAll(url, "{subsearch}", subsearch)
					openbrowser(url)
				}
			}
		}
	} else if checkType == "shodan" {
		if searches != nil {
			for _, search := range searches {
				subsearch := subParams(search, domain, company)
				if subsearch != "" {
					url := "https://www.shodan.io/search?query={subsearch}"
					url = strings.ReplaceAll(url, "{subsearch}", subsearch)
					openbrowser(url)
				}
			}
		}
	} else {
		fmt.Printf("[-] Unknown checkType: %s\n", checkType)
		log.Printf("[-] Unknown checkType: %s\n", checkType)
	}

	if notes != "" {
		subnotes := subParams(notes, domain, company)
		fmt.Printf("[!] [%s]: %s\n", id, subnotes)
	}
}

// Get file name without extension and path only
func fileNameWOExt(filePath string) string {
	fileName := filepath.Base(filePath)
	return strings.TrimSuffix(fileName, filepath.Ext(fileName))
}

// Worker function parses each YAML signature file, opens the URL/runs search on appropriatepath based on type
func worker(sigFileContents map[string]signFileStruct, sigFilesChan chan string,
	domain string, company string, wg *sync.WaitGroup) {

	// Need to let the waitgroup know that the function is done at the end...
	defer wg.Done()

	// Check each signature on the folder to scan

	for sigFile := range sigFilesChan {

		// Get the signature file content previously opened and read
		sigFileContent := sigFileContents[sigFile]

		// First get the list of all checks to perform from file
		myChecks := sigFileContent.Checks

		// Get the check ID from the signature file name itself, if not defined
		// within signature file
		checkID := sigFileContent.ID
		if checkID == "" {
			checkID = fileNameWOExt(sigFile)
		}

		// Now, launch check itself
		for _, myCheck := range myChecks {
			performCheck(checkID, myCheck, domain, company)
		}
	}
	//log.Printf("Completed check on path: %s\n", target["basepath"])
}

func main() {
	pathsWithSigFiles := flag.String("s", "",
		"Files/folders/file-glob patterns, containing YAML signature files")
	domainPtr := flag.String("d", "", "Domain name to investigate")
	companyPtr := flag.String("c", "", "Company name to investigate")
	verbosePtr := flag.Bool("v", false, "Show commands as executed+output")
	maxThreadsPtr := flag.Int("mt", 20, "Max number of goroutines to launch")

	flag.Parse()

	maxThreads := *maxThreadsPtr
	domain := *domainPtr
	company := *companyPtr

	if domain == "" {
		log.Printf("[!] Note: Domain not provided\n")
		//log.Fatalf("[-] Domain must be provided")
	}

	if company == "" {
		log.Printf("[!] Note: Company must be provided")
		//log.Fatalf("[-] Company must be provided")
	}

	// Check if logging should be enabled
	verbose := *verbosePtr
	if !verbose {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	if *pathsWithSigFiles == "" {
		fmt.Println("[-] Signature files must be provided.")
		log.Fatalf("[-] Signature files must be provided.")
	}

	// List of all files in the folders/files above
	var filesToParse []string

	log.Println("Convert the comma-sep list of files, folders to loop through")
	pathsToCheck := strings.Split(*pathsWithSigFiles, ",")

	log.Println("Loop through each path to discover all files")
	for _, pathToCheck := range pathsToCheck {
		// Check if glob file-pattern provided
		log.Printf("Reviewing path: %s\n", pathToCheck)
		if strings.Index(pathToCheck, "*") >= 0 {
			matchingPaths, _ := filepath.Glob(pathToCheck)
			for _, matchingPath := range matchingPaths {
				filesToParse = append(filesToParse, matchingPath)
			}

		} else {

			//Check if file path exists
			fi, err := os.Stat(pathToCheck)
			if err != nil {
				log.Fatalf("[-] Path: %s not found\n", pathToCheck)
			} else {
				switch mode := fi.Mode(); {

				// Add all files from the directory
				case mode.IsDir():
					filepath.Walk(pathToCheck,
						func(path string, f os.FileInfo, err error) error {
							// Determine if the path is actually a file
							fi, err := os.Stat(path)
							if fi.Mode().IsRegular() == true {

								// Add the path if it doesn't already exist to list
								// of all files
								_, found := Find(filesToParse, path)
								if !found {
									filesToParse = append(filesToParse, path)
								}
							}
							return nil
						})

				// Add a single file, if not already present
				case mode.IsRegular():

					// Add the path if it doesn't already exist to list
					// of all files
					_, found := Find(filesToParse, pathToCheck)
					if !found {
						filesToParse = append(filesToParse, pathToCheck)
					}
				}
			}
		}
	}

	log.Printf("Total number of files: %d\n", len(filesToParse))

	// Get all the Yaml files filtered based on the extension
	sigFiles := findSigFiles(filesToParse)

	log.Printf("Number of signature  files: %d\n", len(sigFiles))

	// parse information from each signature file and store it so it doesn't
	// have to be read again & again
	sigFileContents := make(map[string]signFileStruct, len(sigFiles))
	for _, sigFile := range sigFiles {
		log.Printf("Parsing signature file: %s\n", sigFile)
		sigFileContents[sigFile] = parseSigFile(sigFile)
	}

	// Track all the signature files
	sigFilesChan := make(chan string)

	// Starting max number of concurrency threads
	var wg sync.WaitGroup
	for i := 1; i <= maxThreads; i++ {
		wg.Add(1)

		log.Printf("Launching goroutine: %d on domain: %s, company: %s\n", i,
			domain, company)
		go worker(sigFileContents, sigFilesChan, domain, company, &wg)
	}

	// Loop through each signature file and pass it to each thread to process
	for _, sigFile := range sigFiles {
		sigFilesChan <- sigFile
	}

	close(sigFilesChan)

	// Wait for all threads to finish processing the regex checks
	wg.Wait()
}
