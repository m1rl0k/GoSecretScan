package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"strings"
        "flag"
)

const (
	ResetColor    = "\033[0m"
	RedColor      = "\033[31m"
	GreenColor    = "\033[32m"
	YellowColor   = "\033[33m"
	SeparatorLine = "------------------------------------------------------------------------"
)

var secretPatterns = []string{

        `(?i)aws_access_key_id\s*=\s*"?AKIA[0-9A-Z]{16}"?`,
        `(?i)aws_secret_access_key\s*=\s*"?[0-9a-zA-Z/+]{40}"?`,
	`(?i)aws_access_key_id\s*=\s*"AKIA[0-9A-Z]{16}"`,
	`(?i)aws_secret_access_key\s*=\s*"[0-9a-zA-Z/+]{40}"`,
	`(?i)api_key(?:\s*[:=]\s*|\s*["'\s])?([a-zA-Z0-9_\-]{32,})`,
	`(?i)password(?:\s*[:=]\s*|\s*["'\s])?([a-zA-Z0-9!@#$%^&*()_+]{8,})`,
	`(?i)azure_client_(?:id|secret)\s*=\s*"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"`,
	`(?i)azure_tenant_id\s*=\s*"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"`,
	`(?i)azure_subscription_id\s*=\s*"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}"`,
	`(?i)google_application_credentials\s*=\s*"([a-zA-Z0-9\-]+\.json)"`,
	`(?i)google_client_(?:id|secret)\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
	`(?i)google_project(?:\s*[:=]\s*|\s*["'\s])?([a-z][a-z0-9-]{4,28}[a-z0-9])`,
	`(?i)google_credentials(?:\s*[:=]\s*|\s*["'\s])?([a-zA-Z0-9\-]+\.json)"`,
	`(?i)private_key(?:_id)?\s*=\s*"([0-9a-f]{64})"`,
	`(?i)client_email\s*=\s*"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Z]{2,})"`,
	`(?i)client_id\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
	`(?i)client_secret\s*=\s*"([a-zA-Z0-9_]{24})"`,
	`(?i)client_x509_cert_url\s*=\s*"(https://[a-z0-9\-]+\.googleusercontent\.com/[^"']{1,200})"`,
	`(?i)token_uri\s*=\s*"(https://(?:accounts\.)?google\.com/o/oauth2/token)"`,
	`(?i)auth_uri\s*=\s*"(https://(?:accounts\.)?google\.com/o/oauth2/auth)"`,

}

var verbose bool

type Secret struct {
	File       string
	LineNumber int
	Line       string
	Type       string
}

func init() {
	flag.BoolVar(&verbose, "verbose", false, "Display verbose output")
	additionalPatterns := AdditionalSecretPatterns()
	secretPatterns = append(secretPatterns, additionalPatterns...)
}

func main() {
	verbose := false
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--verbose" {
		verbose = true
	}

	setVerbose(verbose)

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	secretsFound := findSecretsInDirectory(dir)

	if len(secretsFound) > 0 {
		displayFoundSecrets(secretsFound)
		os.Exit(1)
	} else {
		fmt.Printf("%sNo secrets found.%s\n", GreenColor, ResetColor)
	}
}

func logVerbose(message string) {
    if verbose {
        fmt.Println(message)
    }
}

func findSecretsInDirectory(dir string) ([]Secret, int, int) {
	var secretsFound []Secret
	var wg sync.WaitGroup
	var mu sync.Mutex
	var scannedFiles, ignoredFiles int

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			if shouldIgnore(path) {
				ignoredFiles++
			} else {
				wg.Add(1)
				go func(p string) {
					defer wg.Done()
					secrets, err := scanFileForSecrets(p)
					if err != nil {
						fmt.Printf("Error scanning file %s: %v\n", p, err)
						return
					}
					mu.Lock()
					secretsFound = append(secretsFound, secrets...)
					mu.Unlock()
				}(path)
				scannedFiles++
			}
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking the directory:", err)
		os.Exit(1)
	}

	wg.Wait()
	return secretsFound, scannedFiles, ignoredFiles
}

func displayFoundSecrets(secretsFound []Secret) {
	fmt.Printf("\n%s%s%s\n", YellowColor, SeparatorLine, ResetColor)
	fmt.Printf("%sSecrets found:%s\n", RedColor, ResetColor)
	for _, secret := range secretsFound {
		fmt.Printf("%sFile:%s %s\n%sLine Number:%s %d\n%sType:%s %s\n%sLine:%s %s\n\n", YellowColor, ResetColor, secret.File, YellowColor, ResetColor, secret.LineNumber, YellowColor, ResetColor, secret.Type, YellowColor, ResetColor, secret.Line)
	}
	fmt.Printf("%s%s\n", YellowColor, SeparatorLine)
	fmt.Printf("%s%d secrets found. Please review and remove them before committing your code.%s\n", RedColor, len(secretsFound), ResetColor)
}

func scanFileForSecrets(path string) ([]Secret, error) {
	logVerbose(fmt.Sprintf("Scanning file: %s", path))

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1
	var secrets []Secret

	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range secretPatterns {
			re := regexp.MustCompile(pattern)
			match := re.FindStringSubmatch(line)
			if len(match) > 0 {
				secretType := "Secret"
				secret := Secret{
					File:       path,
					LineNumber: lineNumber,
					Line:       line,
					Type:       secretType,
				}
				secrets = append(secrets, secret)
			}
		}
		lineNumber++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}

func shouldIgnore(path string) bool {
	ignoreExtensions := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".zip", ".tar", ".gz", ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp",
	}
	ext := filepath.Ext(path)
	for _, ignoreExt := range ignoreExtensions {
		if strings.EqualFold(ignoreExt, ext) {
			return true
		}
	}

	// Ignore .git folder and other specific paths
	ignoredPaths := []string{".git"}
	for _, ignoredPath := range ignoredPaths {
		if strings.Contains(path, ignoredPath) {
			return true
		}
	}

	return false
}

func AdditionalSecretPatterns() []string {
	return []string{
		// Add any additional patterns you want to include here
	}
}

func displaySummary(scannedFiles, ignoredFiles int) {
    fmt.Printf("%sSummary:%s\n", YellowColor, ResetColor)
    fmt.Printf("Scanned Files: %d\n", scannedFiles)
    fmt.Printf("Ignored Files: %d\n", ignoredFiles)
}
