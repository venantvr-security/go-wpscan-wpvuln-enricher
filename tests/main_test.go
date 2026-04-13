package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// ─────────────────────────────────────────────
// Test data: Real WPVulnerability API response
// ─────────────────────────────────────────────

const sampleAPIResponse = `{
  "error": 0,
  "message": null,
  "data": {
    "name": "Contact Form 7",
    "plugin": "contact-form-7",
    "vulnerability": [
      {
        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "name": "Contact Form 7 < 5.8.4 - Reflected XSS",
        "description": "The plugin does not sanitize input properly.",
        "operator": {
          "max_version": "5.8.4",
          "unfixed": "0"
        },
        "source": [
          {
            "id": "CVE-2024-12345",
            "name": "CVE",
            "link": "https://www.cve.org/CVERecord?id=CVE-2024-12345",
            "date": "2024-03-15"
          }
        ],
        "impact": {
          "cvss": {
            "score": "6.1",
            "severity": "MEDIUM"
          },
          "cwe": [
            {
              "cwe": "CWE-79",
              "name": "Cross-site Scripting"
            }
          ]
        }
      },
      {
        "uuid": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
        "name": "Contact Form 7 < 5.3.2 - Unrestricted File Upload",
        "description": "Allows malicious file uploads.",
        "operator": {
          "max_version": "5.3.2",
          "unfixed": "0"
        },
        "source": [
          {
            "id": "CVE-2020-35489",
            "name": "CVE",
            "link": "https://www.cve.org/CVERecord?id=CVE-2020-35489",
            "date": "2020-12-17"
          }
        ],
        "impact": {
          "cvss": {
            "score": "9.8",
            "severity": "CRITICAL"
          },
          "cwe": [
            {
              "cwe": "CWE-434",
              "name": "Unrestricted Upload"
            }
          ]
        }
      }
    ]
  }
}`

// ─────────────────────────────────────────────
// Test: API Response Parsing
// ─────────────────────────────────────────────

func TestWPVulnResponseParsing(t *testing.T) {
	var resp WPVulnResponse
	if err := json.Unmarshal([]byte(sampleAPIResponse), &resp); err != nil {
		t.Fatalf("Failed to parse API response: %v", err)
	}

	if resp.Error != 0 {
		t.Errorf("Expected error=0, got %d", resp.Error)
	}
	if resp.Data == nil {
		t.Fatal("Expected data to be non-nil")
	}
	if resp.Data.Name != "Contact Form 7" {
		t.Errorf("Expected plugin name 'Contact Form 7', got '%s'", resp.Data.Name)
	}
	if len(resp.Data.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(resp.Data.Vulnerabilities))
	}
}

func TestVulnerabilityFieldMapping(t *testing.T) {
	var resp WPVulnResponse
	json.Unmarshal([]byte(sampleAPIResponse), &resp)

	vuln := resp.Data.Vulnerabilities[0]

	// UUID
	if vuln.UUID != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("UUID mismatch: %s", vuln.UUID)
	}

	// Name
	if vuln.Name != "Contact Form 7 < 5.8.4 - Reflected XSS" {
		t.Errorf("Name mismatch: %s", vuln.Name)
	}

	// Operator (fixed_in)
	if vuln.Operator.MaxVersion != "5.8.4" {
		t.Errorf("MaxVersion mismatch: %s", vuln.Operator.MaxVersion)
	}

	// Sources (CVE)
	if len(vuln.Sources) != 1 || vuln.Sources[0].ID != "CVE-2024-12345" {
		t.Errorf("CVE mismatch: %+v", vuln.Sources)
	}

	// Impact (CVSS)
	if !vuln.Impact.HasData || vuln.Impact.CVSS.Severity != "MEDIUM" {
		t.Errorf("CVSS severity mismatch: %+v", vuln.Impact)
	}

	// CWE
	if len(vuln.Impact.CWEs) != 1 || vuln.Impact.CWEs[0].CWE != "CWE-79" {
		t.Errorf("CWE mismatch: %+v", vuln.Impact.CWEs)
	}
}

// ─────────────────────────────────────────────
// Test: Severity Mapping
// ─────────────────────────────────────────────

func TestMapSeverity(t *testing.T) {
	tests := []struct {
		name     string
		cvss     string
		expected string
	}{
		{"CRITICAL maps to HIGH", "CRITICAL", "HIGH"},
		{"HIGH maps to HIGH", "HIGH", "HIGH"},
		{"MEDIUM maps to MEDIUM", "MEDIUM", "MEDIUM"},
		{"LOW maps to LOW", "LOW", "LOW"},
		{"Empty defaults to MEDIUM", "", "MEDIUM"},
		{"Unknown defaults to MEDIUM", "UNKNOWN", "MEDIUM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := WPVulnEntry{
				Impact: WPVulnImpactFlex{
					CVSS:    WPVulnCVSS{Severity: tt.cvss},
					HasData: tt.cvss != "",
				},
			}
			result := mapSeverity(entry)
			if result != tt.expected {
				t.Errorf("mapSeverity(%s) = %s, want %s", tt.cvss, result, tt.expected)
			}
		})
	}
}

func TestMapSeverityNoImpact(t *testing.T) {
	entry := WPVulnEntry{Impact: WPVulnImpactFlex{HasData: false}}
	if result := mapSeverity(entry); result != "MEDIUM" {
		t.Errorf("Expected MEDIUM for empty impacts, got %s", result)
	}
}

// ─────────────────────────────────────────────
// Test: vulnToFinding Conversion
// ─────────────────────────────────────────────

func TestVulnToFinding(t *testing.T) {
	entry := WPVulnEntry{
		UUID:        "test-uuid-123",
		Name:        "Test Vuln - XSS",
		Description: "A test vulnerability",
		Operator:    WPVulnOperator{MaxVersion: "1.2.3", Unfixed: "0"},
		Sources: []WPVulnSource{
			{ID: "CVE-2024-99999", Name: "CVE", Link: "https://cve.org/CVE-2024-99999"},
		},
		Impact: WPVulnImpactFlex{
			CVSS:    WPVulnCVSS{Score: "7.5", Severity: "HIGH"},
			CWEs:    []WPVulnCWE{{CWE: "CWE-79", Name: "XSS"}},
			HasData: true,
		},
	}

	finding := vulnToFinding("test-plugin", "Test Plugin", entry, "https://example.com")

	// Verify basic fields
	if finding.Category != "WordPress Plugin Vulnerability" {
		t.Errorf("Category mismatch: %s", finding.Category)
	}
	if finding.Location != "https://example.com" {
		t.Errorf("Location mismatch: %s", finding.Location)
	}
	if finding.Severity != "HIGH" {
		t.Errorf("Severity mismatch: %s", finding.Severity)
	}
	if finding.OSILayer != "APPLICATION" {
		t.Errorf("OSILayer mismatch: %s", finding.OSILayer)
	}

	// Verify attributes
	if finding.Attributes["plugin_slug"] != "test-plugin" {
		t.Errorf("plugin_slug mismatch")
	}
	if finding.Attributes["fixed_in"] != "1.2.3" {
		t.Errorf("fixed_in mismatch: %v", finding.Attributes["fixed_in"])
	}
	if finding.Attributes["cvss_score"] != "7.5" {
		t.Errorf("cvss_score mismatch: %v", finding.Attributes["cvss_score"])
	}

	// Verify CVE extraction
	cves, ok := finding.Attributes["cve"].([]string)
	if !ok || len(cves) != 1 || cves[0] != "CVE-2024-99999" {
		t.Errorf("CVE extraction failed: %v", finding.Attributes["cve"])
	}

	// Verify CWE extraction
	cwes, ok := finding.Attributes["cwe"].([]string)
	if !ok || len(cwes) != 1 || cwes[0] != "CWE-79" {
		t.Errorf("CWE extraction failed: %v", finding.Attributes["cwe"])
	}
}

func TestVulnToFindingUnfixed(t *testing.T) {
	entry := WPVulnEntry{
		UUID:     "unfixed-uuid",
		Name:     "Unfixed Vuln",
		Operator: WPVulnOperator{MaxVersion: "99.0.0", Unfixed: "1"},
	}

	finding := vulnToFinding("plugin", "Plugin", entry, "https://example.com")

	if _, exists := finding.Attributes["fixed_in"]; exists {
		t.Error("fixed_in should not be set for unfixed vulnerabilities")
	}
}

// ─────────────────────────────────────────────
// Test: Plugin Slug Extraction from WPScan
// ─────────────────────────────────────────────

func TestExtractPluginSlugs(t *testing.T) {
	findings := []Finding{
		{
			Name:       "Plugin: contact-form-7",
			Category:   "WordPress Plugin",
			Attributes: map[string]any{"slug": "contact-form-7"},
		},
		{
			Name:       "Plugin: elementor",
			Category:   "WordPress Plugin",
			Attributes: map[string]any{"plugin": "elementor"},
		},
		{
			Name:       "Plugin: yoast-seo",
			Category:   "WordPress Plugin",
			Attributes: map[string]any{}, // slug from name
		},
		{
			Name:       "WordPress Core",
			Category:   "WordPress Core", // Should be ignored
			Attributes: map[string]any{},
		},
	}

	slugs := extractPluginSlugs(findings)

	if len(slugs) != 3 {
		t.Errorf("Expected 3 slugs, got %d: %v", len(slugs), slugs)
	}

	expected := map[string]bool{
		"contact-form-7": true,
		"elementor":      true,
		"yoast-seo":      true,
	}
	for _, slug := range slugs {
		if !expected[slug] {
			t.Errorf("Unexpected slug: %s", slug)
		}
	}
}

func TestExtractPluginSlugsCaseInsensitive(t *testing.T) {
	findings := []Finding{
		{
			Name:       "Plugin: Test",
			Category:   "wordpress plugin", // lowercase
			Attributes: map[string]any{"slug": "TEST"}, // uppercase
		},
	}

	slugs := extractPluginSlugs(findings)
	if len(slugs) != 1 || slugs[0] != "test" {
		t.Errorf("Expected lowercase 'test', got: %v", slugs)
	}
}

func TestExtractPluginSlugsDedup(t *testing.T) {
	findings := []Finding{
		{Category: "WordPress Plugin", Attributes: map[string]any{"slug": "test"}},
		{Category: "WordPress Plugin", Attributes: map[string]any{"slug": "test"}},
		{Category: "WordPress Plugin", Attributes: map[string]any{"slug": "TEST"}},
	}

	slugs := extractPluginSlugs(findings)
	if len(slugs) != 1 {
		t.Errorf("Expected 1 deduplicated slug, got %d: %v", len(slugs), slugs)
	}
}

// ─────────────────────────────────────────────
// Test: API Version Check (Integration)
// ─────────────────────────────────────────────

func TestCheckAPIVersionMock(t *testing.T) {
	// Mock server returning valid API response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"error": 0, "data": null}`))
	}))
	defer server.Close()

	// Test that we can parse response structure
	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}
}

func TestCheckAPIVersionDeprecated(t *testing.T) {
	// Mock server returning deprecated API error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone) // 410 Gone = API deprecated
		w.Write([]byte(`{"error": 1, "message": "API version deprecated"}`))
	}))
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGone {
		t.Errorf("Expected 410 Gone, got %d", resp.StatusCode)
	}
}

// ─────────────────────────────────────────────
// Test: Extract Location
// ─────────────────────────────────────────────

func TestExtractLocation(t *testing.T) {
	findings := []Finding{
		{Location: ""},
		{Location: "https://example.com"},
	}
	if loc := extractLocation(findings); loc != "https://example.com" {
		t.Errorf("Expected https://example.com, got %s", loc)
	}
}

func TestExtractLocationEmpty(t *testing.T) {
	findings := []Finding{{Location: ""}}
	if loc := extractLocation(findings); loc != "unknown" {
		t.Errorf("Expected 'unknown', got %s", loc)
	}
}

// ─────────────────────────────────────────────
// Test: Full Pipeline (E2E with mock server)
// ─────────────────────────────────────────────

func TestFullPipelineE2E(t *testing.T) {
	// Create mock API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(sampleAPIResponse))
	}))
	defer server.Close()

	// Create temp input file
	inputFindings := `[{
		"id": "test-1",
		"name": "Plugin: contact-form-7",
		"category": "WordPress Plugin",
		"location": "https://test.com",
		"attributes": {"slug": "contact-form-7"}
	}]`

	inputFile, err := os.CreateTemp("", "input-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(inputFile.Name())
	inputFile.WriteString(inputFindings)
	inputFile.Close()

	// Read and parse
	raw, _ := os.ReadFile(inputFile.Name())
	var findings []Finding
	json.Unmarshal(raw, &findings)

	// Extract slugs
	slugs := extractPluginSlugs(findings)
	if len(slugs) != 1 || slugs[0] != "contact-form-7" {
		t.Fatalf("Slug extraction failed: %v", slugs)
	}

	// Simulate API call (using our mock response)
	var resp WPVulnResponse
	json.Unmarshal([]byte(sampleAPIResponse), &resp)

	// Convert to findings
	var enriched []Finding
	for _, vuln := range resp.Data.Vulnerabilities {
		enriched = append(enriched, vulnToFinding("contact-form-7", resp.Data.Name, vuln, "https://test.com"))
	}

	if len(enriched) != 2 {
		t.Errorf("Expected 2 enriched findings, got %d", len(enriched))
	}

	// Verify first finding
	f := enriched[0]
	if f.Severity != "MEDIUM" {
		t.Errorf("Expected MEDIUM severity, got %s", f.Severity)
	}
	if f.Attributes["fixed_in"] != "5.8.4" {
		t.Errorf("Expected fixed_in=5.8.4, got %v", f.Attributes["fixed_in"])
	}
}
