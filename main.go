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
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run main.go <directory_path>")
		os.Exit(1)
	}

	dir := os.Args[1]

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && (filepath.Ext(path) == ".tf" || filepath.Ext(path) == ".txt") {
			err := scanFileForSecrets(path)
			if err != nil {
				fmt.Println("Error scanning file:", err)
			}
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking the directory:", err)
	}
}

func scanFileForSecrets(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1

	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range secretPatterns {
			re := regexp.MustCompile(pattern)
			match := re.FindStringSubmatch(line)
			if len(match) > 0 {
				fmt.Printf("Secret found in file %s at line %d: %s\n", path, lineNumber, line)
			}
		}
		lineNumber++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}
