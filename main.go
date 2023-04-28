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

var secretTypes = []string{
	"API Key",
	"Access Token",
	"Password",
	// Add more secret types here as needed
}


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
	flag.Parse()

	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	secretsFound, totalFiles, totalLines := findSecretsInDirectory(dir)

	if len(secretsFound) > 0 {
		displayFoundSecrets(secretsFound, totalLines, totalFiles)
		os.Exit(1)
	} else {
		fmt.Printf("%sNo secrets found.%s\n", GreenColor, ResetColor)
	}

	if verbose {
		fmt.Printf("%s%d files scanned and %d total lines.%s\n", YellowColor, totalFiles, totalLines, ResetColor)
		displaySummary(totalFiles, len(secretsFound))
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
	var totalFiles int
	var totalLines int

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !shouldIgnore(path) {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				secrets, lines, err := scanFileForSecrets(p)
				if err != nil {
					fmt.Printf("Error scanning file %s: %v\n", p, err)
					return
				}
				mu.Lock()
				secretsFound = append(secretsFound, secrets...)
				totalFiles++
				totalLines += lines
				mu.Unlock()
			}(path)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking the directory:", err)
		os.Exit(1)
	}

	wg.Wait()
	return secretsFound, totalFiles, totalLines
}

func displayFoundSecrets(secretsFound []Secret, totalLines int, totalFiles int) {
	fmt.Printf("\n%s%s%s\n", YellowColor, SeparatorLine, ResetColor)
	fmt.Printf("%sSecrets found:%s\n", RedColor, ResetColor)
	for _, secret := range secretsFound {
		truncatedLine := secret.Line
		if len(truncatedLine) > 100 {
			truncatedLine = truncatedLine[:100] + "..."
		}
		fmt.Printf("%sFile:%s %s\n%sLine Number:%s %d\n%sType:%s %s\n%sLine:%s %s\n\n", YellowColor, ResetColor, secret.File, YellowColor, ResetColor, secret.LineNumber, YellowColor, ResetColor, secret.Type, YellowColor, ResetColor, truncatedLine)
	}
	fmt.Printf("%s%s\n", YellowColor, SeparatorLine)
	fmt.Printf("%s%d secrets found in %d lines across %d files. Please review and remove them before committing your code.%s\n", RedColor, len(secretsFound), totalLines, totalFiles, ResetColor)
}




func scanFileForSecrets(path string) ([]Secret, int, error) {
        if filepath.Base(path) == "main.go" {
        return nil, 0, nil
        }
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1
	var secrets []Secret
	lines := 0

	for scanner.Scan() {
		line := scanner.Text()
		lines++
		for index, pattern := range secretPatterns {
			re := regexp.MustCompile(pattern)
			match := re.FindStringSubmatch(line)
			if len(match) > 0 {
				secretType := "Secret"
				if index < len(secretTypes) {
					secretType = secretTypes[index]
				}
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
		return nil, lines, err
	}

	return secrets, lines, nil
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

	// Ignore the main.go file
	if filepath.Base(path) == "main.go" {
		return true
	}

	// Ignore the binary file
	if filepath.Base(path) == "secret_scanner" {
		return true
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
