package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
        "runtime"
)

const (
	ResetColor    = "\033[0m"
	RedColor      = "\033[31m"
	GreenColor    = "\033[32m"
	YellowColor   = "\033[33m"
	SeparatorLine = "------------------------------------------------------------------------"
)

type Secret struct {
	File       string
	LineNumber int
	Line       string
	Pattern    string
}

func main() {
	// Get the current working directory
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	// Get the secret patterns
	secretPatterns := getSecretPatterns()

	// Use a buffered channel to limit the number of goroutines being created
	jobs := make(chan string, 100)
	results := make(chan []Secret, 1000)

	// Create the worker pool
	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				secrets, err := scanFileForSecrets(job, secretPatterns)
				if err != nil {
					fmt.Println("Error scanning file:", err)
				}
				results <- secrets
			}
		}()
	}

	// Add the jobs to the channel
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !shouldIgnore(path) {
			jobs <- path
		}
		return nil
	})
	if err != nil {
		fmt.Println("Error walking the directory:", err)
	}

	// Close the jobs channel and wait for all the workers to finish
	close(jobs)
	wg.Wait()

	// Merge the results
	var secretsFound []Secret
	for i := 0; i < numWorkers; i++ {
		secrets := <-results
		secretsFound = append(secretsFound, secrets...)
	}

	// Print the results
	if len(secretsFound) > 0 {
		fmt.Printf("\n%s%s%s\n", YellowColor, SeparatorLine, ResetColor)
		fmt.Printf("%sSecrets found:%s\n", RedColor, ResetColor)
		for _, secret := range secretsFound {
			fmt.Printf("%sFile:%s %s\n%sLine Number:%s %d\n%sLine:%s %s\n%sPattern:%s %s\n\n", YellowColor, ResetColor, secret.File, YellowColor, ResetColor, secret.LineNumber, YellowColor, ResetColor, secret.Line, YellowColor, ResetColor, secret.Pattern)
		}
		fmt.Printf("%s%s\n", YellowColor, SeparatorLine)
		fmt.Printf("%s%d secrets found. Please review and remove them before committing your code.%s\n", RedColor, len(secretsFound), ResetColor)
		os.Exit(1) // Exit with a non-zero exit code, indicating a failure
	} else {
		fmt.Printf("%sNo secrets found.%s\n", GreenColor, ResetColor)
	}
}

func shouldIgnore(path string) bool {
    ignorePatterns := []string{
        
        `^node_modules`,        // Node.js modules directory
        `^\.idea`,              // IntelliJ IDEA project directory
        `^\.vscode`,            // Visual Studio Code project directory
        `\.out$`,               // Binary files
        `\.min\.js$`,           // Minified JavaScript files
        `\.min\.css$`,          // Minified CSS files
        `\.(jpg|jpeg|png|gif|ico)$`,    // Images
    }

    for _, pattern := range ignorePatterns {
        re := regexp.MustCompile(pattern)
        if re.MatchString(path) {
            return true
        }
    }

    return false
}

func getSecretPatterns() []*regexp.Regexp {
	defaultPatterns := []string{

        `(?i)access_key\s*=\s*"AKIA[0-9A-Z]{16}"`,
        `(?i)secret_key\s*=\s*"[0-9a-zA-Z/+]{40}"`,	
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
	patterns := append(defaultPatterns, AdditionalSecretPatterns()...)
	var compiledPatterns []*regexp.Regexp
	for _, pattern := range patterns {
		compiledPattern, err := regexp.Compile(pattern)
		if err != nil {
			fmt.Println("Error compiling pattern:", err)
			os.Exit(1)
		}
		compiledPatterns = append(compiledPatterns, compiledPattern)
	}
	return compiledPatterns
}

func scanFileForSecrets(filePath string, secretPatterns []*regexp.Regexp) ([]Secret, error) {
	var secrets []Secret
	file, err := os.Open(filePath)
	if err != nil {
		return secrets, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lineNumber := 1
	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range secretPatterns {
			if pattern.MatchString(line) {
				secrets = append(secrets, Secret{filePath, lineNumber, line, pattern.String()})
			}
		}
		lineNumber++
	}
	if err := scanner.Err(); err != nil {
		return secrets, err
	}
	return secrets, nil
}

func AdditionalSecretPatterns() []string {
	vulnerabilityPatterns := []string{
		// Add your additional regex patterns here
		`(?i)(<\s*script\b[^>]*>(.*?)<\s*/\s*script\s*>)`, // Cross-site scripting (XSS)
		`(?i)(\b(?:or|and)\b\s*[\w-]*\s*=\s*[\w-]*\s*\b(?:or|and)\b\s*[^\s]+)`, // SQL injection
		`(?i)(['"\s]exec(?:ute)?\s*[(\s]*\s*@\w+\s*)`, // SQL injection (EXEC, EXECUTE)
		`(?i)(['"\s]union\s*all\s*select\s*[\w\s,]+(?:from|into|where)\s*\w+)`, // SQL injection (UNION ALL SELECT)
		`(?i)example_pattern_1\s*=\s*"([a-zA-Z0-9\-]+\.example)"`,
		`(?i)example_pattern_2\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
		// Private SSH keys
		`-----BEGIN\sRSA\sPRIVATE\sKEY-----[\s\S]+-----END\sRSA\sPRIVATE\sKEY-----`,
		// S3 Bucket URLs
		`(?i)s3\.amazonaws\.com/[\w\-\.]+`,
		// Hardcoded IP addresses
		`\b(?:\d{1,3}\.){3}\d{1,3}\b`,
		// Basic Authentication credentials
		`(?i)(?:http|https)://\w+:\w+@[\w\-\.]+`,
		// JWT tokens
		`(?i)ey(?:J[a-zA-Z0-9_-]+)[.](?:[a-zA-Z0-9_-]+)[.](?:[a-zA-Z0-9_-]+)`,
		// Email addresses
		`[\w.-]+@[\w.-]+\.\w+`,
		// Connection strings (such as database connections)
		`(?i)(?:Server|Host)=([\w.-]+);\s*(?:Port|Database|User\sID|Password)=([^;\s]+)(?:;\s(?:Port|Database|User\s*ID|Password)=([^;\s]+))*`,
	}
	return vulnerabilityPatterns
}



