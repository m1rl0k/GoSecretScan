package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var secretPatterns = []string{
	`(?i)aws_access_key_id\s*=\s*"(.+)"`,
	`(?i)aws_secret_access_key\s*=\s*"(.+)"`,
	`(?i)api_key\s*=\s*"(.+)"`,
	`(?i)password\s*=\s*"(.+)"`,
	`(?i)azure_client_id\s*=\s*"(.+)"`,
	`(?i)azure_client_secret\s*=\s*"(.+)"`,
	`(?i)azure_tenant_id\s*=\s*"(.+)"`,
	`(?i)azure_subscription_id\s*=\s*"(.+)"`,
	`(?i)google_application_credentials\s*=\s*"(.+)"`,
	`(?i)google_client_id\s*=\s*"(.+)"`,
	`(?i)google_client_secret\s*=\s*"(.+)"`,
	`(?i)google_project\s*=\s*"(.+)"`,
	`(?i)google_credentials\s*=\s*"(.+)"`,
	`(?i)private_key(?:_id)?\s*=\s*"(.+)"`,
	`(?i)client_email\s*=\s*"(.+)"`,
	`(?i)client_id\s*=\s*"(.+)"`,
	`(?i)client_secret\s*=\s*"(.+)"`,
	`(?i)client_x509_cert_url\s*=\s*"(.+)"`,
	`(?i)token_uri\s*=\s*"(.+)"`,
	`(?i)auth_uri\s*=\s*"(.+)"`,
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
