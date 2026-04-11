// Package main - Point d'entrée de l'application
// Ce programme est un "hook" secureCodeBox qui enrichit les résultats de WPScan
// avec des données de vulnérabilités provenant de l'API WPVulnerability.
//
// Flux de données:
//   WPScan findings (JSON) → Extraction des plugins → API WPVulnerability → Findings enrichis
package main

// ═══════════════════════════════════════════════════════════════════════════════
// IMPORTS
// En Go, on importe les packages nécessaires au début du fichier.
// Tous ces packages font partie de la bibliothèque standard (pas de dépendances externes).
// ═══════════════════════════════════════════════════════════════════════════════
import (
	"crypto/rand" // Pour générer des nombres aléatoires cryptographiquement sûrs (UUID)
	"encoding/hex" // Pour convertir des bytes en chaîne hexadécimale
	"encoding/json" // Pour parser et générer du JSON
	"fmt"          // Pour le formatage de chaînes (Printf, Sprintf, Errorf)
	"io"           // Pour les opérations d'entrée/sortie (lecture de body HTTP)
	"log"          // Pour afficher des messages de log avec timestamp
	"net/http"     // Pour faire des requêtes HTTP
	"os"           // Pour lire les variables d'environnement et les fichiers
	"strings"      // Pour manipuler les chaînes de caractères
	"sync"         // Pour la synchronisation des goroutines (WaitGroup)
	"time"         // Pour les durées (timeout, délai de retry)
)

// ═══════════════════════════════════════════════════════════════════════════════
// GÉNÉRATION D'UUID v4
// Un UUID (Universally Unique Identifier) est un identifiant unique de 128 bits.
// Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx (où 4 = version, y = 8,9,a,b)
// ═══════════════════════════════════════════════════════════════════════════════

// newUUID génère un UUID version 4 conforme à la RFC 4122.
// On l'implémente nous-mêmes pour éviter une dépendance externe (comme github.com/google/uuid).
func newUUID() string {
	// Créer un slice de 16 bytes (128 bits)
	// make() alloue et initialise un slice, map ou channel
	b := make([]byte, 16)

	// Remplir avec des octets aléatoires cryptographiquement sûrs
	// rand.Read() remplit le slice avec des bytes aléatoires
	// Le _ ignore le nombre de bytes lus (on sait qu'il y en a 16)
	if _, err := rand.Read(b); err != nil {
		// panic() arrête le programme immédiatement - utilisé pour les erreurs irrécupérables
		panic("crypto/rand unavailable: " + err.Error())
	}

	// Définir la version (4) dans le 7ème byte
	// & 0x0f : garde les 4 bits de poids faible (masque)
	// | 0x40 : met le bit 6 à 1 (version 4)
	b[6] = (b[6] & 0x0f) | 0x40

	// Définir la variante RFC 4122 dans le 9ème byte
	// & 0x3f : garde les 6 bits de poids faible
	// | 0x80 : met les 2 bits de poids fort à 10 (variante RFC 4122)
	b[8] = (b[8] & 0x3f) | 0x80

	// Formater en chaîne UUID standard: 8-4-4-4-12 caractères hex
	// hex.EncodeToString() convertit des bytes en chaîne hexadécimale
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),   // 8 caractères
		hex.EncodeToString(b[4:6]),   // 4 caractères
		hex.EncodeToString(b[6:8]),   // 4 caractères (contient la version)
		hex.EncodeToString(b[8:10]),  // 4 caractères (contient la variante)
		hex.EncodeToString(b[10:16]), // 12 caractères
	)
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCTURES DE DONNÉES - Format secureCodeBox
// En Go, on définit des "struct" pour représenter des objets JSON.
// Les tags `json:"..."` indiquent comment mapper les champs JSON.
// ═══════════════════════════════════════════════════════════════════════════════

// Finding représente un résultat de scan au format secureCodeBox.
// C'est le format standard utilisé par tous les scanners et hooks secureCodeBox.
// Documentation: https://www.securecodebox.io/docs/api/finding
type Finding struct {
	// ID unique du finding (UUID v4)
	ID string `json:"id"`

	// Nom court et descriptif du finding
	Name string `json:"name"`

	// Description détaillée de la vulnérabilité
	Description string `json:"description"`

	// Catégorie du finding (ex: "WordPress Plugin", "WordPress Plugin Vulnerability")
	Category string `json:"category"`

	// URL ou chemin où la vulnérabilité a été trouvée
	Location string `json:"location"`

	// Couche OSI concernée (généralement "APPLICATION" pour les vulnérabilités web)
	OSILayer string `json:"osi_layer"`

	// Niveau de sévérité: "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
	Severity string `json:"severity"`

	// Attributs supplémentaires (CVE, version, etc.)
	// map[string]any = dictionnaire avec clés string et valeurs de n'importe quel type
	Attributes map[string]any `json:"attributes"`

	// Indique si c'est un faux positif
	FalsePositive bool `json:"false_positive"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// STRUCTURES DE DONNÉES - Format API WPVulnerability
// Ces structures correspondent exactement au JSON retourné par l'API.
// Documentation: https://www.wpvulnerability.net/api/plugins/
// ═══════════════════════════════════════════════════════════════════════════════

// WPVulnResponse est l'enveloppe de la réponse API.
// Toutes les réponses de l'API suivent ce format.
type WPVulnResponse struct {
	// Code d'erreur: 0 = succès, autre = erreur
	Error int `json:"error"`

	// Message d'erreur (si Error != 0)
	Message string `json:"message"`

	// Données du plugin (nil si erreur ou plugin non trouvé)
	// Le * indique un pointeur - permet d'avoir nil si absent
	Data *WPVulnPlugin `json:"data"`
}

// WPVulnPlugin contient les informations d'un plugin WordPress.
type WPVulnPlugin struct {
	// Nom affiché du plugin (ex: "Contact Form 7")
	Name string `json:"name"`

	// Slug du plugin (ex: "contact-form-7") - identifiant unique
	Plugin string `json:"plugin"`

	// Liste des vulnérabilités connues pour ce plugin
	// Note: le champ JSON s'appelle "vulnerability" (singulier) mais c'est un tableau
	Vulnerabilities []WPVulnEntry `json:"vulnerability"`
}

// WPVulnEntry représente une vulnérabilité individuelle.
type WPVulnEntry struct {
	// Identifiant unique de la vulnérabilité dans WPVulnerability
	UUID string `json:"uuid"`

	// Titre de la vulnérabilité (ex: "Contact Form 7 < 5.8.4 - Reflected XSS")
	Name string `json:"name"`

	// Description détaillée (peut être vide)
	Description string `json:"description"`

	// Informations sur les versions affectées
	Operator WPVulnOperator `json:"operator"`

	// Sources externes (CVE, JVNDB, etc.)
	Sources []WPVulnSource `json:"source"`

	// Informations d'impact (CVSS, CWE)
	// Note: L'API retourne soit un objet, soit un tableau vide []
	// On utilise un type flexible pour gérer cette inconsistance
	Impact WPVulnImpactFlex `json:"impact"`
}

// WPVulnOperator indique quelles versions sont vulnérables.
type WPVulnOperator struct {
	// Version maximum affectée (la vulnérabilité est corrigée dans cette version)
	MaxVersion string `json:"max_version"`

	// "1" si la vulnérabilité n'est pas encore corrigée, "0" sinon
	Unfixed string `json:"unfixed"`
}

// WPVulnSource représente une source externe (CVE, JVNDB, etc.).
type WPVulnSource struct {
	// Identifiant (ex: "CVE-2024-12345")
	ID string `json:"id"`

	// Type de source (ex: "CVE", "JVNDB")
	Name string `json:"name"`

	// Lien vers la source
	Link string `json:"link"`

	// Date de publication (format YYYY-MM-DD)
	Date string `json:"date"`
}

// WPVulnImpactFlex gère l'inconsistance de l'API où "impact" peut être:
// - Un objet: {"cvss": {...}, "cwe": [...]}
// - Un tableau vide: []
// - Un tableau d'objets: [{"cwe": "...", ...}]
type WPVulnImpactFlex struct {
	// Score CVSS (Common Vulnerability Scoring System)
	CVSS WPVulnCVSS `json:"cvss"`

	// Faiblesses CWE associées
	CWEs []WPVulnCWE `json:"cwe"`

	// Indique si des données d'impact sont présentes
	HasData bool `json:"-"`
}

// UnmarshalJSON implémente json.Unmarshaler pour gérer les différents formats.
// C'est une méthode spéciale que Go appelle automatiquement lors du parsing JSON.
func (i *WPVulnImpactFlex) UnmarshalJSON(data []byte) error {
	// Cas 1: Tableau vide "[]" ou null
	if string(data) == "[]" || string(data) == "null" {
		i.HasData = false
		return nil
	}

	// Cas 2: Essayer de parser comme un objet
	type impactObj struct {
		CVSS WPVulnCVSS  `json:"cvss"`
		CWEs []WPVulnCWE `json:"cwe"`
	}
	var obj impactObj
	if err := json.Unmarshal(data, &obj); err == nil {
		i.CVSS = obj.CVSS
		i.CWEs = obj.CWEs
		i.HasData = true
		return nil
	}

	// Cas 3: Tableau d'objets (on ignore ce cas rare)
	i.HasData = false
	return nil
}

// WPVulnCVSS contient le score CVSS.
type WPVulnCVSS struct {
	// Score numérique (ex: "6.1", "9.8")
	Score string `json:"score"`

	// Sévérité textuelle: "CRITICAL", "HIGH", "MEDIUM", "LOW"
	Severity string `json:"severity"`
}

// WPVulnCWE représente une faiblesse CWE (Common Weakness Enumeration).
type WPVulnCWE struct {
	// Identifiant CWE (ex: "CWE-79" pour XSS)
	CWE string `json:"cwe"`

	// Nom de la faiblesse
	Name string `json:"name"`
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION & CONSTANTES
// Les constantes sont définies avec 'const' et ne peuvent pas être modifiées.
// ═══════════════════════════════════════════════════════════════════════════════

const (
	// Version de cet enrichisseur - à incrémenter à chaque release
	Version = "1.0.0"

	// Version de l'API WPVulnerability avec laquelle ce code est compatible
	// Si l'API change, ce code pourrait ne plus fonctionner
	APIVersion = "2024-01"

	// URL de base pour récupérer les vulnérabilités d'un plugin
	// Usage: wpvulnBaseURL + "contact-form-7" → vulnérabilités du plugin
	wpvulnBaseURL = "https://www.wpvulnerability.net/plugin/"

	// URL pour vérifier que l'API est accessible et compatible
	// On utilise un plugin connu (updraftplus) pour le health check
	wpvulnHealthURL = "https://www.wpvulnerability.net/plugin/updraftplus"

	// Nombre maximum de tentatives pour une requête HTTP
	maxRetries = 3

	// Délai entre chaque tentative en cas d'échec
	retryDelay = 2 * time.Second

	// Timeout pour les requêtes HTTP (évite de bloquer indéfiniment)
	requestTimeout = 15 * time.Second
)

// httpClient est le client HTTP réutilisé pour toutes les requêtes.
// En Go, on évite de créer un nouveau client pour chaque requête (performance).
// 'var' déclare une variable au niveau du package (globale).
var httpClient = &http.Client{Timeout: requestTimeout}

// ═══════════════════════════════════════════════════════════════════════════════
// VÉRIFICATION DE SANTÉ DE L'API
// Appelée au démarrage pour détecter rapidement si l'API est indisponible ou dépréciée.
// ═══════════════════════════════════════════════════════════════════════════════

// checkAPIHealth vérifie que l'API WPVulnerability est accessible et compatible.
// Retourne une erreur si:
// - L'API retourne 410 Gone (dépréciée)
// - La structure de réponse a changé (incompatible)
// - L'API est inaccessible
func checkAPIHealth() error {
	// Afficher la version au démarrage
	log.Printf("[INFO] WPVuln Enricher v%s (API version: %s)", Version, APIVersion)
	log.Printf("[INFO] Checking WPVulnerability API health...")

	// Faire une requête GET vers l'endpoint de test
	resp, err := httpClient.Get(wpvulnHealthURL)
	if err != nil {
		// Erreur réseau (DNS, connexion, etc.)
		return fmt.Errorf("API health check failed: %w", err)
	}
	// defer garantit que resp.Body.Close() sera appelé à la fin de la fonction
	// C'est OBLIGATOIRE pour libérer les ressources réseau
	defer resp.Body.Close()

	// 410 Gone = L'API a été retirée ou cette version n'est plus supportée
	if resp.StatusCode == http.StatusGone {
		return fmt.Errorf("API DEPRECATED: WPVulnerability API returned 410 Gone. "+
			"This enricher version (%s) is no longer compatible. "+
			"Please update to a newer version", Version)
	}

	// 404 peut indiquer que l'endpoint a changé
	if resp.StatusCode == http.StatusNotFound {
		log.Printf("[WARN] API endpoint may have changed (404). Proceeding with caution...")
		return nil // On continue quand même, peut-être que /plugin/ fonctionne
	}

	// Tout autre code que 200 est suspect
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API health check returned unexpected status: %d", resp.StatusCode)
	}

	// Lire le corps de la réponse
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read API response: %w", err)
	}

	// Essayer de parser la réponse avec notre structure
	// Si ça échoue, c'est que le schéma JSON a changé
	var testResp WPVulnResponse
	if err := json.Unmarshal(body, &testResp); err != nil {
		return fmt.Errorf("API SCHEMA CHANGED: Cannot parse response. "+
			"This enricher version (%s) may be incompatible. Error: %w", Version, err)
	}

	// Vérifier si le message contient "deprecated"
	if testResp.Error != 0 && strings.Contains(strings.ToLower(testResp.Message), "deprecat") {
		return fmt.Errorf("API DEPRECATED: %s", testResp.Message)
	}

	log.Printf("[INFO] API health check passed")
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// CLIENT HTTP AVEC RETRY
// Implémente une logique de retry automatique en cas d'échec réseau.
// ═══════════════════════════════════════════════════════════════════════════════

// fetchWithRetry effectue une requête GET avec retry automatique.
// Retourne:
// - (body, nil) si succès
// - (nil, nil) si le plugin n'existe pas (404)
// - (nil, error) si erreur après tous les retries
func fetchWithRetry(url string) ([]byte, error) {
	var lastErr error

	// Boucle de retry
	for attempt := 1; attempt <= maxRetries; attempt++ {
		// Faire la requête HTTP GET
		resp, err := httpClient.Get(url)
		if err != nil {
			// Erreur réseau - on réessaie
			lastErr = fmt.Errorf("attempt %d: request failed: %w", attempt, err)
			log.Printf("[WARN] %s — retry in %s", lastErr, retryDelay)
			time.Sleep(retryDelay)
			continue // Passer à la prochaine itération de la boucle
		}

		// ⚠️ IMPORTANT: On doit fermer le body AVANT de continuer la boucle
		// Sinon on accumule des connexions ouvertes (fuite de ressources)
		body, statusCode := func() ([]byte, int) {
			defer resp.Body.Close()

			if resp.StatusCode == http.StatusNotFound {
				// 404 = Plugin non trouvé dans la base WPVulnerability
				// Ce n'est pas une erreur, juste un plugin inconnu
				return nil, resp.StatusCode
			}

			if resp.StatusCode != http.StatusOK {
				return nil, resp.StatusCode
			}

			// Lire le corps de la réponse
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, -1 // Erreur de lecture
			}
			return body, resp.StatusCode
		}()

		// Traiter les résultats
		if statusCode == http.StatusNotFound {
			return nil, nil // Plugin non trouvé - pas une erreur
		}
		if statusCode == http.StatusOK && body != nil {
			return body, nil // Succès !
		}
		if statusCode == -1 {
			return nil, fmt.Errorf("reading body: %w", err)
		}

		// Autre code HTTP - on réessaie
		lastErr = fmt.Errorf("attempt %d: unexpected status %d", attempt, statusCode)
		log.Printf("[WARN] %s — retry in %s", lastErr, retryDelay)
		time.Sleep(retryDelay)
	}

	// Tous les retries ont échoué
	return nil, fmt.Errorf("all %d attempts failed for %s: %w", maxRetries, url, lastErr)
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXTRACTION DES SLUGS DE PLUGINS
// Parcourt les findings WPScan pour trouver les plugins à enrichir.
// ═══════════════════════════════════════════════════════════════════════════════

// extractPluginSlugs extrait les identifiants uniques (slugs) des plugins WordPress
// trouvés dans les findings WPScan.
//
// Stratégie d'extraction (dans l'ordre de priorité):
// 1. Attribut "slug" explicite
// 2. Attribut "plugin"
// 3. Extraction depuis le nom (format "Plugin: nom-du-plugin")
func extractPluginSlugs(findings []Finding) []string {
	// Map pour dédupliquer les slugs (un slug ne doit apparaître qu'une fois)
	// struct{} est le type vide - utilise 0 bytes de mémoire
	seen := make(map[string]struct{})

	// Slice pour stocker les slugs uniques
	var slugs []string

	// Parcourir tous les findings
	// range retourne l'index et la valeur pour chaque élément
	for _, f := range findings {
		// Ignorer les findings qui ne sont pas des plugins WordPress
		// strings.EqualFold compare sans tenir compte de la casse
		if !strings.EqualFold(f.Category, "WordPress Plugin") {
			continue // Passer au finding suivant
		}

		slug := ""

		// Essai 1: Chercher l'attribut "slug"
		// v, ok := map[key] retourne la valeur et un booléen indiquant si la clé existe
		if v, ok := f.Attributes["slug"]; ok {
			// v.(string) est une "type assertion" - convertit interface{} en string
			// Le _ ignore le booléen de succès (on accepte la chaîne vide si échec)
			slug, _ = v.(string)
		}

		// Essai 2: Chercher l'attribut "plugin" (si slug est vide)
		if slug == "" {
			if v, ok := f.Attributes["plugin"]; ok {
				slug, _ = v.(string)
			}
		}

		// Essai 3: Extraire depuis le nom du finding (ex: "Plugin: contact-form-7")
		if slug == "" {
			// SplitN divise la chaîne en maximum 2 parties
			parts := strings.SplitN(f.Name, ": ", 2)
			if len(parts) == 2 {
				slug = strings.TrimSpace(parts[1]) // Enlever les espaces
			}
		}

		// Si on n'a pas trouvé de slug, passer au suivant
		if slug == "" {
			continue
		}

		// Normaliser en minuscules (les slugs WordPress sont toujours en minuscules)
		slug = strings.ToLower(slug)

		// Ajouter seulement si pas déjà vu (déduplication)
		if _, exists := seen[slug]; !exists {
			seen[slug] = struct{}{} // Marquer comme vu
			slugs = append(slugs, slug) // Ajouter à la liste
		}
	}

	return slugs
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAPPING DE SÉVÉRITÉ
// Convertit la sévérité CVSS vers le format secureCodeBox.
// ═══════════════════════════════════════════════════════════════════════════════

// mapSeverity convertit la sévérité CVSS en sévérité secureCodeBox.
// CVSS utilise: CRITICAL, HIGH, MEDIUM, LOW, NONE
// secureCodeBox utilise: HIGH, MEDIUM, LOW, INFORMATIONAL
func mapSeverity(entry WPVulnEntry) string {
	// Vérifier qu'on a des données d'impact
	if entry.Impact.HasData && entry.Impact.CVSS.Severity != "" {
		// switch est comme un if/else if/else mais plus lisible
		switch strings.ToUpper(entry.Impact.CVSS.Severity) {
		case "CRITICAL", "HIGH":
			return "HIGH" // CRITICAL et HIGH → HIGH
		case "MEDIUM":
			return "MEDIUM"
		case "LOW":
			return "LOW"
		}
	}
	// Par défaut, on considère MEDIUM (principe de prudence)
	return "MEDIUM"
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONVERSION: WPVulnEntry → Finding secureCodeBox
// Transforme une vulnérabilité de l'API en finding secureCodeBox.
// ═══════════════════════════════════════════════════════════════════════════════

// vulnToFinding convertit une entrée WPVulnerability en Finding secureCodeBox.
// Paramètres:
// - slug: identifiant du plugin (ex: "contact-form-7")
// - pluginName: nom affiché du plugin (ex: "Contact Form 7")
// - entry: données de vulnérabilité de l'API
// - location: URL du site scanné
func vulnToFinding(slug string, pluginName string, entry WPVulnEntry, location string) Finding {
	// ── Extraire les CVE et les liens de référence ──
	var cves []string  // Liste des identifiants CVE
	var refs []string  // Liste des liens vers les sources

	// Parcourir toutes les sources de la vulnérabilité
	for _, src := range entry.Sources {
		if src.Name == "CVE" {
			cves = append(cves, src.ID) // Ajouter l'ID CVE
		}
		if src.Link != "" {
			refs = append(refs, src.Link) // Ajouter le lien
		}
	}

	// ── Extraire les CWE (faiblesses) ──
	var cwes []string
	if entry.Impact.HasData {
		for _, cwe := range entry.Impact.CWEs {
			cwes = append(cwes, cwe.CWE)
		}
	}

	// ── Déterminer si la vulnérabilité est corrigée ──
	fixedIn := entry.Operator.MaxVersion
	if entry.Operator.Unfixed == "1" {
		fixedIn = "" // Pas encore de correctif disponible
	}

	// ── Construire les attributs ──
	// map[string]any permet de stocker des valeurs de types différents
	attrs := map[string]any{
		"plugin_slug": slug,
		"plugin_name": pluginName,
		"wpvuln_id":   entry.UUID,
		"references":  refs,
	}

	// Ajouter les attributs optionnels seulement s'ils ont une valeur
	if fixedIn != "" {
		attrs["fixed_in"] = fixedIn
	}
	if len(cves) > 0 {
		attrs["cve"] = cves
	}
	if len(cwes) > 0 {
		attrs["cwe"] = cwes
	}
	if entry.Impact.HasData && entry.Impact.CVSS.Score != "" {
		attrs["cvss_score"] = entry.Impact.CVSS.Score
	}

	// ── Construire la description ──
	desc := entry.Description
	if desc == "" {
		desc = entry.Name // Utiliser le titre si pas de description
	}
	if fixedIn != "" {
		// Ajouter l'info de version corrigée
		desc += fmt.Sprintf(" (fixed in %s)", fixedIn)
	}

	// ── Retourner le Finding complet ──
	return Finding{
		ID:            newUUID(), // Générer un nouvel UUID
		Name:          fmt.Sprintf("[WPVuln] %s — %s", pluginName, entry.Name),
		Description:   desc,
		Category:      "WordPress Plugin Vulnerability",
		Location:      location,
		OSILayer:      "APPLICATION", // Vulnérabilités web = couche application
		Severity:      mapSeverity(entry),
		Attributes:    attrs,
		FalsePositive: false,
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// WORKER: Récupération des vulnérabilités pour un plugin
// Fonction appelée en parallèle pour chaque plugin détecté.
// ═══════════════════════════════════════════════════════════════════════════════

// result encapsule le résultat d'un appel API.
// En Go, on retourne souvent une struct pour grouper plusieurs valeurs.
type result struct {
	findings []Finding // Les findings générés (peut être vide)
	err      error     // L'erreur éventuelle (nil si succès)
}

// fetchVulnsForSlug récupère les vulnérabilités d'un plugin depuis l'API.
// C'est un "worker" qui sera exécuté en parallèle via goroutines.
func fetchVulnsForSlug(slug, location string) result {
	// Construire l'URL de l'API
	url := wpvulnBaseURL + slug
	log.Printf("[INFO] Fetching vulnerabilities for plugin: %s", slug)

	// Faire la requête avec retry
	body, err := fetchWithRetry(url)
	if err != nil {
		return result{err: fmt.Errorf("plugin %s: %w", slug, err)}
	}

	// body == nil signifie que le plugin n'existe pas dans la base
	if body == nil {
		log.Printf("[INFO] Plugin %s not found in WPVulnerability database", slug)
		return result{} // Retourner un résultat vide (pas d'erreur)
	}

	// Parser la réponse JSON
	var resp WPVulnResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return result{err: fmt.Errorf("plugin %s: unmarshal error: %w", slug, err)}
	}

	// Vérifier si l'API a retourné une erreur ou pas de données
	if resp.Error != 0 || resp.Data == nil {
		log.Printf("[INFO] Plugin %s: API returned error or no data", slug)
		return result{}
	}

	plugin := resp.Data

	// Vérifier s'il y a des vulnérabilités
	if len(plugin.Vulnerabilities) == 0 {
		log.Printf("[INFO] No vulnerabilities found for plugin: %s", slug)
		return result{}
	}

	log.Printf("[INFO] Found %d vulnerability(ies) for plugin: %s",
		len(plugin.Vulnerabilities), slug)

	// Convertir chaque vulnérabilité en Finding
	var findings []Finding
	for _, vuln := range plugin.Vulnerabilities {
		findings = append(findings, vulnToFinding(slug, plugin.Name, vuln, location))
	}

	return result{findings: findings}
}

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITAIRE: Extraction de la location
// ═══════════════════════════════════════════════════════════════════════════════

// extractLocation trouve l'URL du site scanné à partir des findings existants.
// Retourne "unknown" si aucune location n'est trouvée.
func extractLocation(findings []Finding) string {
	for _, f := range findings {
		if f.Location != "" {
			return f.Location
		}
	}
	return "unknown"
}

// ═══════════════════════════════════════════════════════════════════════════════
// FONCTION PRINCIPALE (POINT D'ENTRÉE)
// C'est la première fonction exécutée quand le programme démarre.
// ═══════════════════════════════════════════════════════════════════════════════

func main() {
	// ══════════════════════════════════════════════════════════════════════════
	// MODE PARSER: Si activé, exécuter le parser WPScan au lieu du hook
	// ══════════════════════════════════════════════════════════════════════════
	if isParserMode() {
		if err := runParser(); err != nil {
			log.Fatalf("[FATAL] %v", err)
		}
		return
	}

	// ══════════════════════════════════════════════════════════════════════════
	// ÉTAPE 1: Vérification de l'API au démarrage
	// ══════════════════════════════════════════════════════════════════════════
	if err := checkAPIHealth(); err != nil {
		// log.Fatalf affiche le message et termine le programme avec code 1
		log.Fatalf("[FATAL] %v", err)
	}

	// ══════════════════════════════════════════════════════════════════════════
	// ÉTAPE 2: Lecture des variables d'environnement
	// secureCodeBox injecte ces variables automatiquement
	// ══════════════════════════════════════════════════════════════════════════
	readFile := os.Getenv("READ_FILE")   // Chemin du fichier JSON d'entrée
	writeFile := os.Getenv("WRITE_FILE") // Chemin du fichier JSON de sortie

	if readFile == "" {
		log.Fatal("[ERROR] READ_FILE environment variable is not set")
	}

	// ══════════════════════════════════════════════════════════════════════════
	// ÉTAPE 3: Lecture et parsing du fichier de findings WPScan
	// ══════════════════════════════════════════════════════════════════════════
	raw, err := os.ReadFile(readFile)
	if err != nil {
		log.Fatalf("[ERROR] Cannot read findings file %s: %v", readFile, err)
	}

	var findings []Finding
	if err := json.Unmarshal(raw, &findings); err != nil {
		log.Fatalf("[ERROR] Cannot parse findings JSON: %v", err)
	}
	log.Printf("[INFO] Loaded %d finding(s) from %s", len(findings), readFile)

	// ══════════════════════════════════════════════════════════════════════════
	// ÉTAPE 4: Extraction des slugs de plugins
	// ══════════════════════════════════════════════════════════════════════════
	slugs := extractPluginSlugs(findings)
	if len(slugs) == 0 {
		log.Println("[INFO] No WordPress plugin findings detected — nothing to enrich")
		writeOutput(findings, writeFile)
		return // Sortir de main() - le programme se termine
	}
	log.Printf("[INFO] Plugins to check: %v", slugs)

	// Récupérer l'URL du site scanné (pour l'ajouter aux nouveaux findings)
	location := extractLocation(findings)

	// ══════════════════════════════════════════════════════════════════════════
	// ÉTAPE 5: Appels API en parallèle via goroutines
	// Les goroutines sont des threads légers gérés par Go.
	// On lance une goroutine par plugin pour paralléliser les appels API.
	// ══════════════════════════════════════════════════════════════════════════

	// Channel pour recevoir les résultats des goroutines
	// make(chan type, capacité) crée un channel bufferisé
	resultCh := make(chan result, len(slugs))

	// WaitGroup pour attendre que toutes les goroutines terminent
	var wg sync.WaitGroup

	// Lancer une goroutine pour chaque plugin
	for _, slug := range slugs {
		wg.Add(1) // Incrémenter le compteur AVANT de lancer la goroutine

		// go func() lance une nouvelle goroutine (exécution parallèle)
		// On passe 'slug' en paramètre pour éviter les problèmes de closure
		go func(s string) {
			defer wg.Done() // Décrémenter le compteur quand la goroutine termine
			resultCh <- fetchVulnsForSlug(s, location) // Envoyer le résultat dans le channel
		}(slug)
	}

	// Goroutine qui ferme le channel quand tous les workers ont terminé
	// Cela permet au for...range de sortir de sa boucle
	go func() {
		wg.Wait()       // Attendre que toutes les goroutines terminent
		close(resultCh) // Fermer le channel (signale la fin)
	}()

	// ══════════════════════════════════════════════════════════════════════════
	// ÉTAPE 6: Collecte des résultats
	// for...range sur un channel itère jusqu'à sa fermeture
	// ══════════════════════════════════════════════════════════════════════════
	var enriched []Finding
	for res := range resultCh {
		if res.err != nil {
			// Logger l'erreur mais continuer (fail-soft)
			log.Printf("[WARN] %v", res.err)
			continue
		}
		// Ajouter les findings au résultat
		// ... (spread operator) décompresse le slice
		enriched = append(enriched, res.findings...)
	}

	log.Printf("[INFO] %d new vulnerability finding(s) generated", len(enriched))

	// ══════════════════════════════════════════════════════════════════════════
	// ÉTAPE 7: Fusion et écriture des résultats
	// ══════════════════════════════════════════════════════════════════════════
	// append(a, b...) concatène deux slices
	merged := append(findings, enriched...)
	writeOutput(merged, writeFile)
}

// ═══════════════════════════════════════════════════════════════════════════════
// ÉCRITURE DU RÉSULTAT
// ═══════════════════════════════════════════════════════════════════════════════

// writeOutput écrit les findings en JSON dans un fichier ou sur stdout.
func writeOutput(findings []Finding, writeFile string) {
	// MarshalIndent génère du JSON formaté (lisible)
	// "" = pas de préfixe, "  " = indentation de 2 espaces
	out, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		log.Fatalf("[ERROR] Cannot marshal output findings: %v", err)
	}

	if writeFile != "" {
		// Écrire dans le fichier spécifié
		// 0644 = permissions Unix (lecture/écriture pour le propriétaire, lecture pour les autres)
		if err := os.WriteFile(writeFile, out, 0644); err != nil {
			log.Fatalf("[ERROR] Cannot write to %s: %v", writeFile, err)
		}
		log.Printf("[INFO] Results written to %s (%d finding(s) total)", writeFile, len(findings))
	} else {
		// Fallback: écrire sur la sortie standard
		fmt.Println(string(out))
	}
}
