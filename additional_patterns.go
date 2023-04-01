// additional_patterns.go
package main

func AdditionalSecretPatterns() []string {
	return []string{
		// Add your additional regex patterns here
		`(?i)example_pattern_1\s*=\s*"([a-zA-Z0-9\-]+\.example)"`,
		`(?i)example_pattern_2\s*=\s*"([0-9]{12}-[a-zA-Z0-9_]{32})"`,
	}
}
