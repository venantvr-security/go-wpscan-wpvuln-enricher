package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// =============================================================================
// Test Data: Sample WPScan JSON output
// =============================================================================

const sampleWPScanOutput = `{
  "banner": {"description": "WordPress Security Scanner"},
  "start_time": 1712851200,
  "target_url": "https://example.com/",
  "target_ip": "93.184.216.34",
  "effective_url": "https://example.com/",
  "interesting_findings": [
    {
      "url": "https://example.com/readme.html",
      "to_s": "WordPress readme found: https://example.com/readme.html",
      "type": "readme",
      "interesting_entries": []
    }
  ],
  "version": {
    "number": "6.4.3",
    "status": "latest",
    "interesting_entries": [],
    "vulnerabilities": [],
    "found_by": "Meta Generator",
    "confidence": 100
  },
  "plugins": {
    "contact-form-7": {
      "slug": "contact-form-7",
      "location": "https://example.com/wp-content/plugins/contact-form-7/",
      "latest_version": "5.9.3",
      "outdated": true,
      "directory_listing": false,
      "vulnerabilities": [
        {
          "title": "Contact Form 7 < 5.8.4 - Reflected XSS",
          "fixed_in": "5.8.4",
          "references": {
            "cve": ["2024-12345"],
            "url": ["https://wpscan.com/vulnerability/cf7-xss"]
          },
          "cvss": {
            "score": 6.1,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
          }
        }
      ],
      "version": {
        "number": "5.8.0",
        "confidence": 80,
        "found_by": "Readme - Stable Tag"
      },
      "found_by": "Urls In Homepage",
      "confidence": 100
    },
    "elementor": {
      "slug": "elementor",
      "location": "https://example.com/wp-content/plugins/elementor/",
      "latest_version": "3.20.0",
      "outdated": false,
      "vulnerabilities": [],
      "version": {
        "number": "3.20.0",
        "confidence": 100
      }
    }
  },
  "themes": {
    "twentytwentyfour": {
      "slug": "twentytwentyfour",
      "location": "https://example.com/wp-content/themes/twentytwentyfour/",
      "latest_version": "1.0",
      "outdated": false,
      "style_name": "Twenty Twenty-Four",
      "style_uri": "https://wordpress.org/themes/twentytwentyfour/",
      "author": "the WordPress team",
      "vulnerabilities": [],
      "version": {
        "number": "1.0",
        "confidence": 100
      }
    }
  },
  "main_theme": {
    "slug": "twentytwentyfour",
    "style_name": "Twenty Twenty-Four"
  },
  "users": {
    "admin": {
      "id": 1,
      "slug": "admin",
      "description": "",
      "found_by": "Author Id Brute Forcing",
      "confidence": 100
    },
    "editor": {
      "id": 2,
      "slug": "editor",
      "found_by": "Wp Json Api",
      "confidence": 100
    }
  },
  "config_backups": [],
  "db_exports": [],
  "stop_time": 1712851260,
  "elapsed": 60.5,
  "requests_done": 1234
}`

const sampleWPScanWithBackups = `{
  "target_url": "https://vulnerable.com/",
  "effective_url": "https://vulnerable.com/",
  "interesting_findings": [],
  "version": {
    "number": "5.0.0",
    "status": "insecure",
    "vulnerabilities": [
      {
        "title": "WordPress 5.0.0 - RCE",
        "fixed_in": "5.0.1",
        "references": {"cve": ["2019-8942"]},
        "cvss": {"score": 9.8}
      }
    ]
  },
  "plugins": {},
  "themes": {},
  "users": {},
  "config_backups": [
    {"url": "https://vulnerable.com/wp-config.php.bak"}
  ],
  "db_exports": [
    {"url": "https://vulnerable.com/backup.sql"}
  ]
}`

// =============================================================================
// Test: Parse function
// =============================================================================

func TestParseBasic(t *testing.T) {
	findings, err := Parse([]byte(sampleWPScanOutput))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("Expected findings, got none")
	}

	// Should have: version + interesting + 2 plugins + 1 theme + 2 users = 7+ findings
	if len(findings) < 7 {
		t.Errorf("Expected at least 7 findings, got %d", len(findings))
	}
}

func TestParseVersion(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanOutput))

	var versionFinding *Finding
	for i := range findings {
		if findings[i].Category == "WordPress Version" {
			versionFinding = &findings[i]
			break
		}
	}

	if versionFinding == nil {
		t.Fatal("Version finding not found")
	}

	if !strings.Contains(versionFinding.Name, "6.4.3") {
		t.Errorf("Version name should contain '6.4.3': %s", versionFinding.Name)
	}

	if versionFinding.Severity != "INFORMATIONAL" {
		t.Errorf("Expected INFORMATIONAL for latest version, got %s", versionFinding.Severity)
	}
}

func TestParseInsecureVersion(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanWithBackups))

	var versionFinding *Finding
	for i := range findings {
		if findings[i].Category == "WordPress Version" {
			versionFinding = &findings[i]
			break
		}
	}

	if versionFinding == nil {
		t.Fatal("Version finding not found")
	}

	if versionFinding.Severity != "HIGH" {
		t.Errorf("Expected HIGH for insecure version, got %s", versionFinding.Severity)
	}
}

func TestParsePlugins(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanOutput))

	pluginCount := 0
	var cf7Finding *Finding

	for i := range findings {
		if findings[i].Category == "WordPress Plugin" {
			pluginCount++
			if strings.Contains(findings[i].Name, "contact-form-7") {
				cf7Finding = &findings[i]
			}
		}
	}

	if pluginCount != 2 {
		t.Errorf("Expected 2 plugin findings, got %d", pluginCount)
	}

	if cf7Finding == nil {
		t.Fatal("contact-form-7 finding not found")
	}

	// Check outdated detection
	if cf7Finding.Severity != "LOW" {
		t.Errorf("Expected LOW for outdated plugin, got %s", cf7Finding.Severity)
	}

	// Check attributes
	if cf7Finding.Attributes["slug"] != "contact-form-7" {
		t.Errorf("Slug mismatch: %v", cf7Finding.Attributes["slug"])
	}
}

func TestParsePluginVulnerabilities(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanOutput))

	vulnCount := 0
	for _, f := range findings {
		if f.Category == "WordPress Vulnerability" {
			vulnCount++
		}
	}

	if vulnCount < 1 {
		t.Errorf("Expected at least 1 vulnerability finding, got %d", vulnCount)
	}
}

func TestParseUsers(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanOutput))

	userCount := 0
	var adminFinding *Finding

	for i := range findings {
		if findings[i].Category == "WordPress User" {
			userCount++
			if strings.Contains(findings[i].Name, "admin") {
				adminFinding = &findings[i]
			}
		}
	}

	if userCount != 2 {
		t.Errorf("Expected 2 user findings, got %d", userCount)
	}

	if adminFinding == nil {
		t.Fatal("admin user finding not found")
	}

	if adminFinding.Attributes["user_id"] != 1 {
		t.Errorf("User ID mismatch: %v", adminFinding.Attributes["user_id"])
	}
}

func TestParseThemes(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanOutput))

	themeCount := 0
	for _, f := range findings {
		if f.Category == "WordPress Theme" {
			themeCount++
		}
	}

	// themes map has 1, main_theme adds another (but might be deduplicated)
	if themeCount < 1 {
		t.Errorf("Expected at least 1 theme finding, got %d", themeCount)
	}
}

func TestParseConfigBackups(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanWithBackups))

	var backupFinding *Finding
	for i := range findings {
		if findings[i].Category == "WordPress Backup" && strings.Contains(findings[i].Name, "Configuration") {
			backupFinding = &findings[i]
			break
		}
	}

	if backupFinding == nil {
		t.Fatal("Config backup finding not found")
	}

	if backupFinding.Severity != "HIGH" {
		t.Errorf("Expected HIGH severity for config backup, got %s", backupFinding.Severity)
	}
}

func TestParseDBExports(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanWithBackups))

	var dbFinding *Finding
	for i := range findings {
		if findings[i].Category == "WordPress Backup" && strings.Contains(findings[i].Name, "Database") {
			dbFinding = &findings[i]
			break
		}
	}

	if dbFinding == nil {
		t.Fatal("DB export finding not found")
	}

	if dbFinding.Severity != "HIGH" {
		t.Errorf("Expected HIGH severity for DB export, got %s", dbFinding.Severity)
	}
}

func TestParseInterestingFindings(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanOutput))

	interestingCount := 0
	for _, f := range findings {
		if f.Category == "WordPress Interesting Finding" {
			interestingCount++
		}
	}

	if interestingCount < 1 {
		t.Errorf("Expected at least 1 interesting finding, got %d", interestingCount)
	}
}

// =============================================================================
// Test: Error handling
// =============================================================================

func TestParseInvalidJSON(t *testing.T) {
	_, err := Parse([]byte("not valid json"))
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestParseEmptyJSON(t *testing.T) {
	findings, err := Parse([]byte("{}"))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	// Empty WPScan output should produce no findings
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for empty JSON, got %d", len(findings))
	}
}

// =============================================================================
// Test: isParserMode
// =============================================================================

func TestIsParserModeEnvVar(t *testing.T) {
	os.Setenv("PARSER_MODE", "true")
	defer os.Unsetenv("PARSER_MODE")

	if !isParserMode() {
		t.Error("Expected isParserMode() to return true when PARSER_MODE=true")
	}
}

func TestIsParserModeDefault(t *testing.T) {
	os.Unsetenv("PARSER_MODE")
	// Reset os.Args to avoid test pollution
	oldArgs := os.Args
	os.Args = []string{"test"}
	defer func() { os.Args = oldArgs }()

	if isParserMode() {
		t.Error("Expected isParserMode() to return false by default")
	}
}

// =============================================================================
// Test: Finding JSON serialization
// =============================================================================

func TestFindingJSONRoundTrip(t *testing.T) {
	original := Finding{
		ID:          "test-uuid",
		Name:        "Test Finding",
		Description: "A test",
		Category:    "Test Category",
		Location:    "https://example.com",
		OSILayer:    "APPLICATION",
		Severity:    "HIGH",
		Attributes: map[string]any{
			"key1": "value1",
			"key2": 42,
		},
		FalsePositive: false,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var parsed Finding
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if parsed.ID != original.ID {
		t.Errorf("ID mismatch: %s vs %s", parsed.ID, original.ID)
	}
	if parsed.Severity != original.Severity {
		t.Errorf("Severity mismatch: %s vs %s", parsed.Severity, original.Severity)
	}
}

// =============================================================================
// Test: runParser with file I/O
// =============================================================================

func TestRunParserWithFiles(t *testing.T) {
	// Create temp input file
	inputFile, err := os.CreateTemp("", "wpscan-input-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(inputFile.Name())
	inputFile.WriteString(sampleWPScanOutput)
	inputFile.Close()

	// Create temp output file
	outputFile, err := os.CreateTemp("", "findings-output-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	// Set environment variables
	os.Setenv("READ_FILE", inputFile.Name())
	os.Setenv("WRITE_FILE", outputFile.Name())
	defer os.Unsetenv("READ_FILE")
	defer os.Unsetenv("WRITE_FILE")

	// Run parser
	err = runParser()
	if err != nil {
		t.Fatalf("runParser failed: %v", err)
	}

	// Verify output
	output, err := os.ReadFile(outputFile.Name())
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var findings []Finding
	if err := json.Unmarshal(output, &findings); err != nil {
		t.Fatalf("Failed to parse output: %v", err)
	}

	if len(findings) < 7 {
		t.Errorf("Expected at least 7 findings, got %d", len(findings))
	}
}

func TestRunParserMissingFile(t *testing.T) {
	os.Setenv("READ_FILE", "/nonexistent/file.json")
	defer os.Unsetenv("READ_FILE")

	err := runParser()
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

// =============================================================================
// Test: Vulnerability CVSS severity mapping
// =============================================================================

func TestParseVulnerabilityCVSSSeverity(t *testing.T) {
	tests := []struct {
		name     string
		cvss     float64
		expected string
	}{
		{"Critical CVSS 9.8", 9.8, "HIGH"},
		{"High CVSS 7.5", 7.5, "HIGH"},
		{"Medium CVSS 5.0", 5.0, "MEDIUM"},
		{"Low CVSS 2.5", 2.5, "LOW"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vuln := WPScanVulnerability{
				Title: "Test Vuln",
				CVSS:  &WPScanCVSS{Score: tt.cvss},
			}
			finding := parseVulnerability(vuln, "test-plugin", "https://example.com")
			if finding.Severity != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, finding.Severity)
			}
		})
	}
}

func TestParseVulnerabilityNoCVSS(t *testing.T) {
	vuln := WPScanVulnerability{
		Title: "Test Vuln Without CVSS",
	}
	finding := parseVulnerability(vuln, "test-plugin", "https://example.com")
	if finding.Severity != "MEDIUM" {
		t.Errorf("Expected MEDIUM for no CVSS, got %s", finding.Severity)
	}
}

// =============================================================================
// Test: Location extraction
// =============================================================================

func TestParseLocationFromEffectiveURL(t *testing.T) {
	findings, _ := Parse([]byte(sampleWPScanOutput))

	// All findings should have the effective_url as location
	for _, f := range findings {
		if f.Location != "https://example.com/" && f.Location != "https://example.com/readme.html" {
			// Some findings (like interesting findings) have their own URL
			if f.Category != "WordPress Interesting Finding" {
				t.Errorf("Unexpected location: %s (category: %s)", f.Location, f.Category)
			}
		}
	}
}
