package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var secretPatterns = []string{
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

type Secret struct {
	File       string
	LineNumber int
	Line       string
}

func main() {
	// Get the current working directory
	dir, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	var secretsFound []Secret

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (filepath.Ext(path) == ".tf" || filepath.Ext(path) == ".txt") {
			secrets, err := scanFileForSecrets(path)
			if err != nil {
				fmt.Println("Error scanning file:", err)
			}
			secretsFound = append(secretsFound, secrets...)
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking the directory:", err)
	}

	// Format and print the results
	fmt.Println("Secrets found:")
	for _, secret := range secretsFound {
		fmt.Printf("File: %s\nLine Number: %d\nLine: %s\n\n", secret.File, secret.LineNumber, secret.Line)
	}
}

func scanFileForSecrets(path string) ([]Secret, error) {
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
				secrets = append(secrets, Secret{
					File:       path,
					LineNumber: lineNumber,
					Line:       line,
				})
			}
		}
		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}
    if len(secretsFound) > 0 {
        fmt.Println("Secrets found:")
        for _, secret := range secretsFound {
            fmt.Printf("File: %s\nLine Number: %d\nLine: %s\n\n", secret.File, secret.LineNumber, secret.Line)
        }
        os.Exit(1) // Exit with a non-zero exit code, indicating a failure
    } else {
        fmt.Println("No secrets found.")
    }
}
