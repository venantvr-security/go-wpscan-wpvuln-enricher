// Package main - WPScan Parser pour secureCodeBox
// Ce parser convertit la sortie JSON brute de WPScan en format Finding secureCodeBox.
//
// Usage:
//   READ_FILE=/path/to/wpscan-results.json WRITE_FILE=/path/to/findings.json ./parser
//
// Ou en mode stdin/stdout:
//   cat wpscan-results.json | ./parser > findings.json
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// =============================================================================
// STRUCTURES DE DONNÉES - Format WPScan brut
// =============================================================================

// WPScanResult représente la sortie JSON complète de WPScan
type WPScanResult struct {
	Banner            map[string]any          `json:"banner"`
	StartTime         int64                   `json:"start_time"`
	StartMemory       int64                   `json:"start_memory"`
	TargetURL         string                  `json:"target_url"`
	TargetIP          string                  `json:"target_ip"`
	EffectiveURL      string                  `json:"effective_url"`
	InterestingFindings []WPScanInteresting   `json:"interesting_findings"`
	Version           *WPScanVersion          `json:"version"`
	MainTheme         *WPScanTheme            `json:"main_theme"`
	Plugins           map[string]WPScanPlugin `json:"plugins"`
	Themes            map[string]WPScanTheme  `json:"themes"`
	Users             map[string]WPScanUser   `json:"users"`
	ConfigBackups     []WPScanBackup          `json:"config_backups"`
	DBExports         []WPScanBackup          `json:"db_exports"`
	PasswordAttack    *WPScanPasswordAttack   `json:"password_attack"`
	StopTime          int64                   `json:"stop_time"`
	Elapsed           float64                 `json:"elapsed"`
	RequestsDone      int                     `json:"requests_done"`
	CachedRequests    int                     `json:"cached_requests"`
	DataSent          int64                   `json:"data_sent"`
	DataSentHumanised string                  `json:"data_sent_humanised"`
	DataReceived      int64                   `json:"data_received"`
	UsedMemory        int64                   `json:"used_memory"`
}

// WPScanInteresting représente un finding intéressant
type WPScanInteresting struct {
	URL               string         `json:"url"`
	ToS               string         `json:"to_s"`
	Type              string         `json:"type"`
	InterestingEntries []string      `json:"interesting_entries"`
	References        map[string]any `json:"references"`
}

// WPScanVersion représente la version WordPress détectée
type WPScanVersion struct {
	Number            string                `json:"number"`
	Status            string                `json:"status"`
	InterestingEntries []string             `json:"interesting_entries"`
	Vulnerabilities   []WPScanVulnerability `json:"vulnerabilities"`
	FoundBy           string                `json:"found_by"`
	Confidence        int                   `json:"confidence"`
}

// WPScanPlugin représente un plugin détecté
type WPScanPlugin struct {
	Slug              string                `json:"slug"`
	Location          string                `json:"location"`
	LatestVersion     string                `json:"latest_version"`
	LastUpdated       string                `json:"last_updated"`
	OutdatedVersion   bool                  `json:"outdated"`
	Readme            map[string]any        `json:"readme"`
	DirectoryListing  bool                  `json:"directory_listing"`
	ErrorLog          string                `json:"error_log"`
	InterestingEntries []string             `json:"interesting_entries"`
	Vulnerabilities   []WPScanVulnerability `json:"vulnerabilities"`
	Version           *WPScanComponentVer   `json:"version"`
	FoundBy           string                `json:"found_by"`
	Confidence        int                   `json:"confidence"`
}

// WPScanTheme représente un thème détecté
type WPScanTheme struct {
	Slug              string                `json:"slug"`
	Location          string                `json:"location"`
	LatestVersion     string                `json:"latest_version"`
	LastUpdated       string                `json:"last_updated"`
	OutdatedVersion   bool                  `json:"outdated"`
	StyleURL          string                `json:"style_url"`
	StyleName         string                `json:"style_name"`
	StyleURI          string                `json:"style_uri"`
	Description       string                `json:"description"`
	Author            string                `json:"author"`
	AuthorURI         string                `json:"author_uri"`
	Template          string                `json:"template"`
	License           string                `json:"license"`
	LicenseURI        string                `json:"license_uri"`
	Tags              string                `json:"tags"`
	TextDomain        string                `json:"text_domain"`
	Parents           []WPScanTheme         `json:"parents"`
	DirectoryListing  bool                  `json:"directory_listing"`
	ErrorLog          string                `json:"error_log"`
	InterestingEntries []string             `json:"interesting_entries"`
	Vulnerabilities   []WPScanVulnerability `json:"vulnerabilities"`
	Version           *WPScanComponentVer   `json:"version"`
	FoundBy           string                `json:"found_by"`
	Confidence        int                   `json:"confidence"`
}

// WPScanUser représente un utilisateur détecté
type WPScanUser struct {
	ID                int    `json:"id"`
	Slug              string `json:"slug"`
	Description       string `json:"description"`
	FoundBy           string `json:"found_by"`
	Confidence        int    `json:"confidence"`
	InterestingEntries []string `json:"interesting_entries"`
}

// WPScanVulnerability représente une vulnérabilité
type WPScanVulnerability struct {
	Title      string              `json:"title"`
	FixedIn    string              `json:"fixed_in"`
	References WPScanVulnRefs      `json:"references"`
	CVSS       *WPScanCVSS         `json:"cvss"`
}

// WPScanVulnRefs contient les références de la vulnérabilité
type WPScanVulnRefs struct {
	CVE      []string `json:"cve"`
	URL      []string `json:"url"`
	WPVulnDB []string `json:"wpvulndb"`
	Metasploit []string `json:"metasploit"`
	ExploitDB []string `json:"exploitdb"`
	YouTube  []string `json:"youtube"`
}

// WPScanCVSS contient le score CVSS
type WPScanCVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
}

// WPScanComponentVer contient la version d'un composant
type WPScanComponentVer struct {
	Number     string `json:"number"`
	Confidence int    `json:"confidence"`
	FoundBy    string `json:"found_by"`
}

// WPScanBackup représente un fichier de backup trouvé
type WPScanBackup struct {
	URL string `json:"url"`
}

// WPScanPasswordAttack représente les résultats d'attaque par mot de passe
type WPScanPasswordAttack struct {
	// Les champs dépendent du type d'attaque
}

// =============================================================================
// CONVERSION EN FORMAT FINDING
// =============================================================================

// Parse convertit la sortie WPScan en findings secureCodeBox
func Parse(raw []byte) ([]Finding, error) {
	var result WPScanResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse WPScan JSON: %w", err)
	}

	var findings []Finding
	location := result.EffectiveURL
	if location == "" {
		location = result.TargetURL
	}

	// 1. Version WordPress
	if result.Version != nil {
		findings = append(findings, parseVersion(result.Version, location)...)
	}

	// 2. Interesting Findings
	for _, item := range result.InterestingFindings {
		findings = append(findings, parseInteresting(item, location))
	}

	// 3. Plugins
	for slug, plugin := range result.Plugins {
		findings = append(findings, parsePlugin(slug, plugin, location)...)
	}

	// 4. Themes
	for slug, theme := range result.Themes {
		findings = append(findings, parseTheme(slug, theme, location)...)
	}

	// 5. Main Theme
	if result.MainTheme != nil {
		findings = append(findings, parseTheme(result.MainTheme.Slug, *result.MainTheme, location)...)
	}

	// 6. Users
	for username, user := range result.Users {
		findings = append(findings, parseUser(username, user, location))
	}

	// 7. Config Backups
	for _, backup := range result.ConfigBackups {
		findings = append(findings, parseConfigBackup(backup, location))
	}

	// 8. DB Exports
	for _, export := range result.DBExports {
		findings = append(findings, parseDBExport(export, location))
	}

	return findings, nil
}

func parseVersion(v *WPScanVersion, location string) []Finding {
	var findings []Finding

	// Finding pour la version elle-même
	severity := "INFORMATIONAL"
	if v.Status == "insecure" {
		severity = "HIGH"
	} else if v.Status == "outdated" {
		severity = "MEDIUM"
	}

	findings = append(findings, Finding{
		ID:          newUUID(),
		Name:        fmt.Sprintf("WordPress Version %s", v.Number),
		Description: fmt.Sprintf("WordPress version %s detected (status: %s)", v.Number, v.Status),
		Category:    "WordPress Version",
		Location:    location,
		OSILayer:    "APPLICATION",
		Severity:    severity,
		Attributes: map[string]any{
			"version":    v.Number,
			"status":     v.Status,
			"found_by":   v.FoundBy,
			"confidence": v.Confidence,
		},
	})

	// Findings pour les vulnérabilités de la version
	for _, vuln := range v.Vulnerabilities {
		findings = append(findings, parseVulnerability(vuln, "WordPress Core", location))
	}

	return findings
}

func parseInteresting(item WPScanInteresting, location string) Finding {
	return Finding{
		ID:          newUUID(),
		Name:        item.ToS,
		Description: fmt.Sprintf("Interesting finding: %s", item.ToS),
		Category:    "WordPress Interesting Finding",
		Location:    item.URL,
		OSILayer:    "APPLICATION",
		Severity:    "INFORMATIONAL",
		Attributes: map[string]any{
			"type":               item.Type,
			"interesting_entries": item.InterestingEntries,
		},
	}
}

func parsePlugin(slug string, plugin WPScanPlugin, location string) []Finding {
	var findings []Finding

	// Finding pour le plugin lui-même
	severity := "INFORMATIONAL"
	desc := fmt.Sprintf("Plugin %s detected", slug)

	if plugin.Version != nil {
		desc = fmt.Sprintf("Plugin %s version %s detected", slug, plugin.Version.Number)
	}
	if plugin.OutdatedVersion {
		severity = "LOW"
		desc += " (outdated)"
	}

	attrs := map[string]any{
		"slug":     slug,
		"plugin":   slug,
		"location": plugin.Location,
	}
	if plugin.Version != nil {
		attrs["version"] = plugin.Version.Number
		attrs["confidence"] = plugin.Version.Confidence
	}
	if plugin.LatestVersion != "" {
		attrs["latest_version"] = plugin.LatestVersion
	}
	if plugin.DirectoryListing {
		attrs["directory_listing"] = true
	}

	findings = append(findings, Finding{
		ID:          newUUID(),
		Name:        fmt.Sprintf("Plugin: %s", slug),
		Description: desc,
		Category:    "WordPress Plugin",
		Location:    location,
		OSILayer:    "APPLICATION",
		Severity:    severity,
		Attributes:  attrs,
	})

	// Findings pour les vulnérabilités du plugin
	for _, vuln := range plugin.Vulnerabilities {
		findings = append(findings, parseVulnerability(vuln, slug, location))
	}

	return findings
}

func parseTheme(slug string, theme WPScanTheme, location string) []Finding {
	var findings []Finding

	if slug == "" {
		slug = theme.StyleName
	}
	if slug == "" {
		return findings
	}

	severity := "INFORMATIONAL"
	desc := fmt.Sprintf("Theme %s detected", slug)

	if theme.Version != nil {
		desc = fmt.Sprintf("Theme %s version %s detected", slug, theme.Version.Number)
	}
	if theme.OutdatedVersion {
		severity = "LOW"
		desc += " (outdated)"
	}

	attrs := map[string]any{
		"slug":     slug,
		"location": theme.Location,
	}
	if theme.Version != nil {
		attrs["version"] = theme.Version.Number
	}
	if theme.Author != "" {
		attrs["author"] = theme.Author
	}

	findings = append(findings, Finding{
		ID:          newUUID(),
		Name:        fmt.Sprintf("Theme: %s", slug),
		Description: desc,
		Category:    "WordPress Theme",
		Location:    location,
		OSILayer:    "APPLICATION",
		Severity:    severity,
		Attributes:  attrs,
	})

	// Findings pour les vulnérabilités du thème
	for _, vuln := range theme.Vulnerabilities {
		findings = append(findings, parseVulnerability(vuln, slug, location))
	}

	return findings
}

func parseUser(username string, user WPScanUser, location string) Finding {
	return Finding{
		ID:          newUUID(),
		Name:        fmt.Sprintf("User: %s", username),
		Description: fmt.Sprintf("WordPress user '%s' enumerated (ID: %d)", username, user.ID),
		Category:    "WordPress User",
		Location:    location,
		OSILayer:    "APPLICATION",
		Severity:    "INFORMATIONAL",
		Attributes: map[string]any{
			"username":   username,
			"user_id":    user.ID,
			"slug":       user.Slug,
			"found_by":   user.FoundBy,
			"confidence": user.Confidence,
		},
	}
}

func parseVulnerability(vuln WPScanVulnerability, component string, location string) Finding {
	severity := "MEDIUM"
	if vuln.CVSS != nil {
		if vuln.CVSS.Score >= 9.0 {
			severity = "HIGH"
		} else if vuln.CVSS.Score >= 7.0 {
			severity = "HIGH"
		} else if vuln.CVSS.Score >= 4.0 {
			severity = "MEDIUM"
		} else {
			severity = "LOW"
		}
	}

	desc := vuln.Title
	if vuln.FixedIn != "" {
		desc += fmt.Sprintf(" (fixed in %s)", vuln.FixedIn)
	}

	attrs := map[string]any{
		"component": component,
		"title":     vuln.Title,
	}
	if vuln.FixedIn != "" {
		attrs["fixed_in"] = vuln.FixedIn
	}
	if len(vuln.References.CVE) > 0 {
		attrs["cve"] = vuln.References.CVE
	}
	if len(vuln.References.URL) > 0 {
		attrs["references"] = vuln.References.URL
	}
	if len(vuln.References.WPVulnDB) > 0 {
		attrs["wpvulndb"] = vuln.References.WPVulnDB
	}
	if vuln.CVSS != nil {
		attrs["cvss_score"] = vuln.CVSS.Score
		attrs["cvss_vector"] = vuln.CVSS.Vector
	}

	return Finding{
		ID:          newUUID(),
		Name:        fmt.Sprintf("[Vulnerability] %s — %s", component, vuln.Title),
		Description: desc,
		Category:    "WordPress Vulnerability",
		Location:    location,
		OSILayer:    "APPLICATION",
		Severity:    severity,
		Attributes:  attrs,
	}
}

func parseConfigBackup(backup WPScanBackup, location string) Finding {
	return Finding{
		ID:          newUUID(),
		Name:        "Configuration Backup Found",
		Description: fmt.Sprintf("WordPress configuration backup file found at %s", backup.URL),
		Category:    "WordPress Backup",
		Location:    backup.URL,
		OSILayer:    "APPLICATION",
		Severity:    "HIGH",
		Attributes: map[string]any{
			"type": "config_backup",
			"url":  backup.URL,
		},
	}
}

func parseDBExport(export WPScanBackup, location string) Finding {
	return Finding{
		ID:          newUUID(),
		Name:        "Database Export Found",
		Description: fmt.Sprintf("WordPress database export file found at %s", export.URL),
		Category:    "WordPress Backup",
		Location:    export.URL,
		OSILayer:    "APPLICATION",
		Severity:    "HIGH",
		Attributes: map[string]any{
			"type": "db_export",
			"url":  export.URL,
		},
	}
}

// =============================================================================
// POINT D'ENTRÉE DU PARSER
// =============================================================================

func runParser() error {
	log.SetFlags(log.Ltime)
	log.Println("[INFO] WPScan Parser v1.0.0 starting...")

	// Lire l'entrée
	readFile := os.Getenv("READ_FILE")
	var raw []byte
	var err error

	if readFile != "" {
		log.Printf("[INFO] Reading from file: %s", readFile)
		raw, err = os.ReadFile(readFile)
	} else {
		log.Println("[INFO] Reading from stdin...")
		raw, err = io.ReadAll(os.Stdin)
	}

	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if len(raw) == 0 {
		return fmt.Errorf("empty input")
	}

	// Parser
	log.Println("[INFO] Parsing WPScan results...")
	findings, err := Parse(raw)
	if err != nil {
		return err
	}

	log.Printf("[INFO] Generated %d finding(s)", len(findings))

	// Écrire la sortie
	output, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	writeFile := os.Getenv("WRITE_FILE")
	if writeFile != "" {
		log.Printf("[INFO] Writing to file: %s", writeFile)
		if err := os.WriteFile(writeFile, output, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
	} else {
		fmt.Println(string(output))
	}

	log.Println("[INFO] Parser completed successfully")
	return nil
}

// Pour exécuter en mode parser (si appelé avec --parser ou si PARSER_MODE=true)
func isParserMode() bool {
	if os.Getenv("PARSER_MODE") == "true" {
		return true
	}
	for _, arg := range os.Args[1:] {
		if strings.TrimPrefix(arg, "-") == "parser" || strings.TrimPrefix(arg, "--") == "parser" {
			return true
		}
	}
	return false
}
