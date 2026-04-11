# ═══════════════════════════════════════════════════════════════════════════════
# DOCKERFILE - WPScan WPVuln Enricher
# Build multi-stage pour une image finale minimale et sécurisée (0 CVE)
# ═══════════════════════════════════════════════════════════════════════════════

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 1: Compilation
# Image Chainguard Go - maintenue avec 0 CVE connues
# https://images.chainguard.dev/directory/image/go/overview
# ───────────────────────────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/go:latest AS builder

# Répertoire de travail pour la compilation
WORKDIR /work

# Copier le fichier de module Go
# Note: pas de go.sum car aucune dépendance externe
COPY go.mod ./

# Copier le code source et les tests
COPY main.go parser.go main_test.go ./

# Exécuter les tests unitaires pendant le build
# Si un test échoue, le build échoue (fail-fast)
RUN go test -v ./...

# Compiler le binaire
# CGO_ENABLED=0 : pas de dépendance à la libc (binaire statique)
# GOOS=linux    : cible Linux
# GOARCH=amd64  : architecture x86_64
# -ldflags="-w -s" : supprimer les infos de debug (binaire plus petit)
# -trimpath    : supprimer les chemins locaux (reproductibilité)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -ldflags="-w -s" \
      -trimpath \
      -o /work/go-wpscan-wpvuln-enricher \
      .

# ───────────────────────────────────────────────────────────────────────────────
# STAGE 2: Image d'exécution
# Image Chainguard static - la plus petite image possible avec certificats TLS
# https://images.chainguard.dev/directory/image/static/overview
# ───────────────────────────────────────────────────────────────────────────────
FROM cgr.dev/chainguard/static:latest

# Labels OCI standard pour la traçabilité
LABEL org.opencontainers.image.title="WPScan WPVuln Enricher"
LABEL org.opencontainers.image.description="secureCodeBox hook to enrich WPScan findings with WPVulnerability data"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/venantvr-security/go-wpscan-wpvuln-enricher"
LABEL org.opencontainers.image.licenses="MIT"

# Labels custom pour la version de l'API
LABEL com.wpvulnerability.api-version="2024-01"
LABEL com.wpvulnerability.api-docs="https://www.wpvulnerability.net/api/plugins/"

# Copier le binaire depuis le stage de build
COPY --from=builder /work/go-wpscan-wpvuln-enricher /go-wpscan-wpvuln-enricher

# Variables d'environnement par défaut
# secureCodeBox injecte READ_FILE et WRITE_FILE automatiquement
ENV READ_FILE=/tmp/findings.json
ENV WRITE_FILE=/tmp/findings.json

# Point d'entrée - le binaire à exécuter
ENTRYPOINT ["/go-wpscan-wpvuln-enricher"]
