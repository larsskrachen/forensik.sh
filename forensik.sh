#!/usr/bin/env bash
# forensik.sh — Docker Forensics CLI (All-in-One)
# Autor: Lars | April 2026
# Bash 3.2 kompatibel (macOS default)

set -euo pipefail

################################################################################
# FARBEN & FORMATIERUNG
################################################################################

RED=$'\033[0;31m'
YLW=$'\033[1;33m'
GRN=$'\033[0;32m'
BLU=$'\033[0;34m'
CYN=$'\033[0;36m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
NC=$'\033[0m'

################################################################################
# GLOBALE PFADE
################################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_BASE="${SCRIPT_DIR}/forensic-results"
DEMO_DIR="${SCRIPT_DIR}/demo-target"

################################################################################
# ANALYSE-GLOBALS (werden von init_analysis gesetzt)
################################################################################

TARGET=""
CASE_ID=""
SKIP_EXPORT=0
OUT=""
AUDIT=""
SUMMARY=""
IOC_FILE=""
SHA256_MANIFEST=""
COC=""
FINDINGS_TMP=""

CONTAINER_ID=""
CONTAINER_NAME=""
IMAGE_REF=""
IMAGE_ID=""
STATUS=""
RUNNING=""
CREATED=""

TIMESTAMP=""
TS_HUMAN=""
ANALYST=""
START_EPOCH=""
FORENSIC_IMG=""
DIFF_COUNT=0

################################################################################
# HELPER-FUNKTIONEN
################################################################################

_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "${AUDIT}"
}

step() {
    local msg="$*"
    echo ""
    echo -e "${BOLD}${CYN}┌─[ ${msg} ]${NC}"
    _log "STEP: ${msg}"
}

ok() {
    echo -e "  ${GRN}✓ $*${NC}"
    _log "OK: $*"
}

warn() {
    echo -e "  ${YLW}⚠ $*${NC}"
    _log "WARN: $*"
}

skip() {
    echo -e "  ${DIM}↷ $* (übersprungen)${NC}"
    _log "SKIP: $*"
}

ioc() {
    local severity="$1"
    local category="$2"
    local desc="$3"
    local line="[${severity}] ${category}: ${desc}"
    echo -e "  ${RED}${line}${NC}"
    echo "${line}" >> "${IOC_FILE}"
    echo "${line}" >> "${FINDINGS_TMP}"
    _log "IOC: ${line}"
}

run_in() {
    if [[ "${RUNNING}" == "true" ]]; then
        docker exec "${CONTAINER_ID}" "$@" 2>/dev/null || true
    else
        echo "(Container gestoppt)"
    fi
}

find_secrets() {
    grep -iE '(password|secret|token|api[._]key|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36})' \
        | grep -viE '(DEMO|NOT_REAL|XXXXX|example|placeholder|your_|changeme)' \
        || true
}

sha256_cmd() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$@"
    else
        shasum -a 256 "$@"
    fi
}

hash_evidence() {
    local file="$1"
    if [[ -f "${file}" ]]; then
        local hash
        hash=$(sha256_cmd "${file}" | awk '{print $1}')
        echo "${hash}  ${file}" >> "${SHA256_MANIFEST}"
        _log "HASH: ${file} => ${hash}"
    fi
}

press_enter() {
    echo ""
    echo -e "${DIM}  [Enter drücken zum Fortfahren...]${NC}"
    read -r _pe_dummy || true
}

################################################################################
# BANNER
################################################################################

show_banner() {
    clear
    echo -e "${BOLD}${CYN}"
    cat << 'BANNER'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              Docker Forensics Suite — forensik.sh v1.0                      ║
║          Computerforensik · Chain of Custody · IOC-Analyse                  ║
║                    Autor: Lars Stimpel | April 2026                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
BANNER
    echo -e "${NC}"
}

################################################################################
# INITIALISIERUNG DER ANALYSE
################################################################################

init_analysis() {
    local container_input="$1"
    CASE_ID="${2:-}"
    SKIP_EXPORT="${3:-0}"

    # Container validieren
    if ! docker inspect "${container_input}" &>/dev/null; then
        echo -e "${RED}Fehler: Container '${container_input}' nicht gefunden.${NC}" >&2
        exit 1
    fi

    # Metadaten aus inspect laden
    CONTAINER_ID=$(docker inspect --format '{{.Id}}' "${container_input}")
    CONTAINER_NAME=$(docker inspect --format '{{.Name}}' "${container_input}" | sed 's|^/||')
    IMAGE_REF=$(docker inspect --format '{{.Config.Image}}' "${container_input}")
    IMAGE_ID=$(docker inspect --format '{{.Image}}' "${container_input}" | cut -c1-12)
    STATUS=$(docker inspect --format '{{.State.Status}}' "${container_input}")
    RUNNING=$(docker inspect --format '{{.State.Running}}' "${container_input}")
    CREATED=$(docker inspect --format '{{.Created}}' "${container_input}")

    TARGET="${container_input}"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    TS_HUMAN=$(date '+%Y-%m-%d %H:%M:%S')
    ANALYST=$(whoami)
    START_EPOCH=$(date +%s)

    # Case-ID
    if [[ -z "${CASE_ID}" ]]; then
        CASE_ID="CASE-$(date +%Y%m%d)-$(echo "${CONTAINER_NAME}" | tr '[:lower:]' '[:upper:]' | tr -cd 'A-Z0-9' | cut -c1-6)"
    fi

    # Ausgabeverzeichnis
    local safe_name
    safe_name=$(echo "${CONTAINER_NAME}" | tr -cd 'a-zA-Z0-9_-' | cut -c1-40)
    OUT="${RESULTS_BASE}/${safe_name}_${TIMESTAMP}"
    mkdir -p "${OUT}"

    # Unterverzeichnisse anlegen
    mkdir -p \
        "${OUT}/01_metadata" \
        "${OUT}/02_volatile" \
        "${OUT}/03_filesystem" \
        "${OUT}/04_image" \
        "${OUT}/05_logs" \
        "${OUT}/06_network" \
        "${OUT}/07_evidence" \
        "${OUT}/08_report" \
        "${OUT}/09_ramdump"

    # Log-Dateien
    AUDIT="${OUT}/AUDIT.log"
    SUMMARY="${OUT}/ZUSAMMENFASSUNG.md"
    IOC_FILE="${OUT}/05_logs/ioc_findings.txt"
    SHA256_MANIFEST="${OUT}/07_evidence/SHA256_MANIFEST.txt"
    COC="${OUT}/07_evidence/chain_of_custody.txt"
    FINDINGS_TMP="${OUT}/.findings_tmp"

    touch "${AUDIT}" "${IOC_FILE}" "${SHA256_MANIFEST}" "${FINDINGS_TMP}"

    # Forensik-Image-Name
    FORENSIC_IMG="forensic-$(echo "${CONTAINER_NAME}" | tr -cd 'a-z0-9-' | cut -c1-20)-${TIMESTAMP}"

    # Chain of Custody initialisieren
    cat > "${COC}" << EOF
CHAIN OF CUSTODY — Docker Forensics
====================================
Fall-ID:          ${CASE_ID}
Container-Name:   ${CONTAINER_NAME}
Container-ID:     ${CONTAINER_ID}
Image:            ${IMAGE_REF}
Status:           ${STATUS}
Analyst:          ${ANALYST}
Erstellungszeit:  ${TS_HUMAN}
Ausgabepfad:      ${OUT}
Host-System:      $(uname -a)
Docker-Version:   $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unbekannt")

EREIGNISSE:
===========
EOF

    _log "Analyse initialisiert: Container=${CONTAINER_NAME} Case=${CASE_ID}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Analyse gestartet von ${ANALYST}" >> "${COC}"
}

################################################################################
# PHASE 1: METADATEN
################################################################################

phase_metadata() {
    step "Phase 1: Container-Metadaten & Inventar"

    # docker inspect vollständig
    docker inspect "${CONTAINER_ID}" 2>/dev/null | jq '.' > "${OUT}/01_metadata/container_inspect.json" || true
    ok "container_inspect.json gespeichert"

    # Übersicht
    cat > "${OUT}/01_metadata/overview.json" << EOF
{
  "case_id": "${CASE_ID}",
  "container_id": "${CONTAINER_ID}",
  "container_name": "${CONTAINER_NAME}",
  "image_ref": "${IMAGE_REF}",
  "image_id": "${IMAGE_ID}",
  "status": "${STATUS}",
  "running": ${RUNNING},
  "created": "${CREATED}",
  "analyst": "${ANALYST}",
  "timestamp": "${TS_HUMAN}"
}
EOF
    ok "overview.json gespeichert"

    # Mounts
    docker inspect --format '{{json .Mounts}}' "${CONTAINER_ID}" \
        2>/dev/null | jq '.' > "${OUT}/01_metadata/mounts.json" || echo "[]" > "${OUT}/01_metadata/mounts.json"
    local mount_count
    mount_count=$(docker inspect --format '{{len .Mounts}}' "${CONTAINER_ID}" 2>/dev/null || echo "0")
    if [[ "${mount_count}" -gt 0 ]]; then
        warn "${mount_count} Mount(s) gefunden — prüfe mounts.json"
    else
        ok "Keine Mounts"
    fi

    # Docker-Info
    docker info --format '{{json .}}' 2>/dev/null | jq '.' > "${OUT}/01_metadata/docker_info.json" || true
    ok "docker_info.json gespeichert"

    # Image-Inspect
    docker inspect "${IMAGE_REF}" 2>/dev/null | jq '.' > "${OUT}/01_metadata/image_inspect.json" \
        || docker inspect "${IMAGE_ID}" 2>/dev/null | jq '.' > "${OUT}/01_metadata/image_inspect.json" \
        || echo "{}" > "${OUT}/01_metadata/image_inspect.json"
    ok "image_inspect.json gespeichert"

    # Alle Container
    docker ps -a --format '{{json .}}' 2>/dev/null | jq -s '.' > "${OUT}/01_metadata/all_containers.json" || true

    # Netzwerke und Volumes
    docker network ls 2>/dev/null > "${OUT}/01_metadata/networks.txt" || true
    docker volume ls 2>/dev/null > "${OUT}/01_metadata/volumes.txt" || true
    ok "Netzwerke und Volumes inventarisiert"

    # Capabilities-Check
    local caps
    caps=$(docker inspect --format '{{json .HostConfig.CapAdd}}' "${CONTAINER_ID}" 2>/dev/null || echo "null")
    local privileged
    privileged=$(docker inspect --format '{{.HostConfig.Privileged}}' "${CONTAINER_ID}" 2>/dev/null || echo "false")

    if [[ "${privileged}" == "true" ]]; then
        ioc "KRITISCH" "Capabilities" "Container läuft im PRIVILEGED-Modus"
    fi
    if [[ "${caps}" != "null" && "${caps}" != "[]" && -n "${caps}" ]]; then
        ioc "HOCH" "Capabilities" "Zusätzliche Capabilities: ${caps}"
    fi

    # Sicherheits-Checks
    local security_opt
    security_opt=$(docker inspect --format '{{json .HostConfig.SecurityOpt}}' "${CONTAINER_ID}" 2>/dev/null || echo "[]")
    if echo "${security_opt}" | grep -q "no-new-privileges"; then
        ok "no-new-privileges gesetzt"
    else
        warn "no-new-privileges nicht gesetzt"
    fi

    local pid_mode
    pid_mode=$(docker inspect --format '{{.HostConfig.PidMode}}' "${CONTAINER_ID}" 2>/dev/null || echo "")
    if [[ "${pid_mode}" == "host" ]]; then
        ioc "KRITISCH" "Namespace" "PID-Namespace: host (vollständiger Host-Zugriff)"
    fi

    local net_mode
    net_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "${CONTAINER_ID}" 2>/dev/null || echo "")
    if [[ "${net_mode}" == "host" ]]; then
        ioc "HOCH" "Namespace" "Netzwerk-Namespace: host"
    fi

    local read_only
    read_only=$(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "${CONTAINER_ID}" 2>/dev/null || echo "false")
    if [[ "${read_only}" == "true" ]]; then
        ok "Rootfs ist read-only"
    else
        warn "Rootfs ist beschreibbar"
    fi

    _log "Phase 1 abgeschlossen"
}

################################################################################
# PHASE 2: VOLATILE DATEN
################################################################################

phase_volatile() {
    step "Phase 2: Volatile Daten (ENV-Vars, Prozesse, Verbindungen)"

    # ENV-Variablen
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${CONTAINER_ID}" \
        2>/dev/null > "${OUT}/02_volatile/env_vars_docker_inspect.txt" || true
    run_in env 2>/dev/null > "${OUT}/02_volatile/env_vars.txt" || true

    local env_count
    env_count=$(wc -l < "${OUT}/02_volatile/env_vars.txt" | tr -d ' \n\r')
    ok "${env_count} ENV-Variablen gespeichert"

    if [[ "${RUNNING}" == "true" ]]; then
        # Prozesse (innerhalb des Containers)
        run_in ps auxf > "${OUT}/02_volatile/processes.txt" 2>/dev/null || \
            run_in ps aux > "${OUT}/02_volatile/processes.txt" 2>/dev/null || true

        # docker top (Host-Perspektive mit Host-PIDs)
        docker top "${CONTAINER_ID}" aux 2>/dev/null > "${OUT}/02_volatile/docker_top.txt" || \
            docker top "${CONTAINER_ID}" 2>/dev/null > "${OUT}/02_volatile/docker_top.txt" || true
        local top_count
        top_count=$(grep -c -v '^UID\|^USER' "${OUT}/02_volatile/docker_top.txt" 2>/dev/null || true)
        top_count="${top_count:-0}"
        ok "docker top: ${top_count} Prozesse (Host-PIDs)"

        # Statistiken
        docker stats "${CONTAINER_ID}" --no-stream 2>/dev/null \
            > "${OUT}/02_volatile/stats.txt" || true

        # Netzwerkverbindungen
        run_in ss -tlnp 2>/dev/null > "${OUT}/06_network/routing.txt" || true
        run_in netstat -an 2>/dev/null > "${OUT}/02_volatile/network_connections.txt" \
            || run_in ss -an 2>/dev/null > "${OUT}/02_volatile/network_connections.txt" || true

        grep -i 'ESTABLISHED' "${OUT}/02_volatile/network_connections.txt" \
            > "${OUT}/02_volatile/established_connections.txt" 2>/dev/null || true
        local conn_count
        conn_count=$(wc -l < "${OUT}/02_volatile/established_connections.txt" | tr -d ' \n\r')
        if [[ "${conn_count}" -gt 0 ]]; then
            warn "${conn_count} aktive ESTABLISHED-Verbindungen"
        fi

        # Offene File-Deskriptoren
        run_in ls -la /proc/1/fd 2>/dev/null > "${OUT}/02_volatile/open_fds.txt" || true
        ok "Volatile Daten gesammelt (Prozesse, Verbindungen, FDs)"
    else
        skip "Container gestoppt — keine Laufzeit-Daten verfügbar"
        for f in processes.txt docker_top.txt stats.txt network_connections.txt established_connections.txt open_fds.txt; do
            echo "(Container gestoppt)" > "${OUT}/02_volatile/${f}"
        done
    fi

    _log "Phase 2 abgeschlossen"
}

################################################################################
# PHASE 3: DATEISYSTEM
################################################################################

phase_filesystem() {
    step "Phase 3: Dateisystem-Analyse"

    # docker diff
    docker diff "${CONTAINER_ID}" 2>/dev/null > "${OUT}/03_filesystem/docker_diff.txt" || true
    DIFF_COUNT=$(wc -l < "${OUT}/03_filesystem/docker_diff.txt" | tr -d ' \n\r')
    ok "docker diff: ${DIFF_COUNT} geänderte Einträge"
    if [[ "${DIFF_COUNT}" -gt 100 ]]; then
        warn "Hohe Anzahl an Dateisystem-Änderungen: ${DIFF_COUNT}"
    fi

    if [[ "${RUNNING}" == "true" ]]; then
        # SUID-Binaries
        local known_suid="/usr/bin/sudo /usr/bin/su /bin/mount /bin/umount /usr/bin/mount /usr/bin/umount /usr/bin/newgrp /usr/bin/passwd /usr/bin/chfn /usr/bin/chsh /usr/bin/gpasswd /usr/bin/pkexec /usr/bin/at /usr/lib/openssh/ssh-keysign /sbin/unix_chkpwd /usr/lib/dbus-1.0/dbus-daemon-launch-helper"

        run_in find / -perm -4000 -type f 2>/dev/null \
            > "${OUT}/03_filesystem/suid_binaries.txt" || true
        run_in find / -perm -2000 -type f 2>/dev/null \
            > "${OUT}/03_filesystem/sgid_binaries.txt" || true

        local suid_count=0
        while IFS= read -r binary; do
            [[ -z "${binary}" ]] && continue
            local is_known=0
            for k in ${known_suid}; do
                [[ "${binary}" == "${k}" ]] && is_known=1 && break
            done
            if [[ "${is_known}" -eq 0 ]]; then
                ioc "HOCH" "SUID-Binary" "Unbekannte SUID-Binary: ${binary}"
                suid_count=$((suid_count + 1))
            fi
        done < "${OUT}/03_filesystem/suid_binaries.txt"
        if [[ "${suid_count}" -eq 0 ]]; then
            ok "Keine unbekannten SUID-Binaries"
        fi

        # World-writable
        run_in find / -perm -0002 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null \
            > "${OUT}/03_filesystem/world_writable_files.txt" || true
        local ww_count
        ww_count=$(wc -l < "${OUT}/03_filesystem/world_writable_files.txt" | tr -d ' \n\r')
        if [[ "${ww_count}" -gt 5 ]]; then
            ioc "MITTEL" "Dateisystem" "${ww_count} world-writable Dateien gefunden"
        fi

        # Versteckte Dateien an verdächtigen Orten
        run_in find /tmp /var/tmp /dev/shm -name '.*' -type f 2>/dev/null \
            > "${OUT}/03_filesystem/hidden_files_suspicious.txt" || true
        local hidden_count
        hidden_count=$(wc -l < "${OUT}/03_filesystem/hidden_files_suspicious.txt" | tr -d ' \n\r')
        if [[ "${hidden_count}" -gt 0 ]]; then
            ioc "MITTEL" "Dateisystem" "${hidden_count} versteckte Dateien in /tmp, /var/tmp, /dev/shm"
        fi

        # Bash-History
        run_in cat /root/.bash_history 2>/dev/null \
            > "${OUT}/03_filesystem/bash_history_root.txt" || true
        run_in find /home -name '.bash_history' -exec cat {} \; 2>/dev/null \
            > "${OUT}/03_filesystem/bash_history_users.txt" || true

        # Verdächtige History-Einträge
        cat "${OUT}/03_filesystem/bash_history_root.txt" "${OUT}/03_filesystem/bash_history_users.txt" 2>/dev/null \
            | grep -iE '(wget|curl|nc|ncat|nmap|base64|chmod \+x|\.sh|python|perl|ruby|/tmp/|/dev/shm|reverse|backdoor|exploit)' \
            > "${OUT}/03_filesystem/bash_history_suspicious.txt" 2>/dev/null || true
        local hist_susp
        hist_susp=$(wc -l < "${OUT}/03_filesystem/bash_history_suspicious.txt" | tr -d ' \n\r')
        if [[ "${hist_susp}" -gt 0 ]]; then
            ioc "HOCH" "Shell-History" "${hist_susp} verdächtige Befehle in Bash-History"
        else
            ok "Keine verdächtigen Befehle in Bash-History"
        fi

        # System-Dateien
        run_in cat /etc/passwd 2>/dev/null > "${OUT}/03_filesystem/passwd.txt" || true
        run_in cat /etc/shadow 2>/dev/null > "${OUT}/03_filesystem/shadow.txt" || true
        run_in cat /etc/sudoers 2>/dev/null > "${OUT}/03_filesystem/sudoers.txt" || true

        # Zusätzliche Sudo-Einträge
        local sudo_count
        sudo_count=$(grep -v '^#' "${OUT}/03_filesystem/sudoers.txt" 2>/dev/null \
            | grep -c 'NOPASSWD' || true)
        if [[ "${sudo_count}" -gt 0 ]]; then
            ioc "HOCH" "Sudo" "${sudo_count} NOPASSWD-Einträge in sudoers"
        fi

        # Passwd — verdächtige UIDs
        if grep -q ':0:' "${OUT}/03_filesystem/passwd.txt" 2>/dev/null; then
            local root_count
            root_count=$(grep -c ':0:' "${OUT}/03_filesystem/passwd.txt" || true)
            if [[ "${root_count}" -gt 1 ]]; then
                ioc "KRITISCH" "Passwd" "${root_count} User mit UID 0 (root-Äquivalent)"
            fi
        fi

        # Cron-Jobs
        {
            run_in crontab -l 2>/dev/null || true
            run_in cat /etc/crontab 2>/dev/null || true
            run_in ls -la /etc/cron* 2>/dev/null || true
        } > "${OUT}/03_filesystem/cron_jobs.txt" || true

        # SSH-Keys
        run_in find / -name 'authorized_keys' -o -name 'id_rsa' -o -name 'id_ed25519' 2>/dev/null \
            > "${OUT}/03_filesystem/ssh_keys.txt" || true
        local ssh_count
        ssh_count=$(wc -l < "${OUT}/03_filesystem/ssh_keys.txt" | tr -d ' \n\r')
        if [[ "${ssh_count}" -gt 0 ]]; then
            warn "${ssh_count} SSH-Key-Dateien gefunden"
        fi

        # /etc/hosts
        run_in cat /etc/hosts 2>/dev/null > "${OUT}/03_filesystem/etc_hosts.txt" || true

        # Config-Secrets suchen
        run_in find /etc /app /var/www /opt /srv /home \
            -type f \( -name '*.conf' -o -name '*.cfg' -o -name '*.env' -o -name '*.yml' -o -name '*.yaml' -o -name '*.ini' -o -name '*.json' \) \
            2>/dev/null \
            | head -50 \
            | while read -r f; do
                run_in cat "${f}" 2>/dev/null || true
              done \
            | find_secrets \
            > "${OUT}/03_filesystem/config_secrets.txt" 2>/dev/null || true

        local cfg_secrets
        cfg_secrets=$(wc -l < "${OUT}/03_filesystem/config_secrets.txt" | tr -d ' \n\r')
        if [[ "${cfg_secrets}" -gt 0 ]]; then
            ioc "HOCH" "Config-Secrets" "${cfg_secrets} potenzielle Secrets in Konfigurationsdateien"
        fi

        # Webshells
        run_in find /var/www /srv /app /opt /tmp 2>/dev/null \
            -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' -o -name '*.py' -o -name '*.rb' \) \
            -exec grep -l 'eval\|exec\|system\|passthru\|shell_exec\|proc_open\|base64_decode' {} \; \
            2>/dev/null > "${OUT}/03_filesystem/webshells_found.txt" || true
        local ws_count
        ws_count=$(wc -l < "${OUT}/03_filesystem/webshells_found.txt" | tr -d ' \n\r')
        if [[ "${ws_count}" -gt 0 ]]; then
            ioc "KRITISCH" "Webshell" "${ws_count} potenzielle Webshells gefunden"
        fi

        # /tmp-Inhalt
        run_in ls -laR /tmp /var/tmp 2>/dev/null > "${OUT}/03_filesystem/tmp_contents.txt" || true

        ok "Dateisystem-Analyse abgeschlossen"
    else
        skip "Eingeschränkte Dateisystem-Analyse (Container gestoppt)"
        # docker diff ist auch bei gestopptem Container verfügbar, bereits gespeichert
        for f in suid_binaries.txt sgid_binaries.txt world_writable_files.txt hidden_files_suspicious.txt \
                  bash_history_root.txt bash_history_users.txt bash_history_suspicious.txt \
                  passwd.txt shadow.txt sudoers.txt cron_jobs.txt ssh_keys.txt etc_hosts.txt \
                  config_secrets.txt webshells_found.txt tmp_contents.txt; do
            echo "(Container gestoppt)" > "${OUT}/03_filesystem/${f}"
        done
    fi

    _log "Phase 3 abgeschlossen"
}

################################################################################
# PHASE 4: IMAGE-ANALYSE
################################################################################

phase_image() {
    step "Phase 4: Image-Analyse (History, Layers, Secrets)"

    # Docker History vollständig
    docker history --no-trunc "${IMAGE_REF}" 2>/dev/null \
        > "${OUT}/04_image/docker_history_full.txt" \
        || docker history --no-trunc "${IMAGE_ID}" 2>/dev/null \
        > "${OUT}/04_image/docker_history_full.txt" || true
    ok "Docker-History gespeichert"

    # Secrets in Layer-Commands suchen
    find_secrets < "${OUT}/04_image/docker_history_full.txt" \
        > "${OUT}/04_image/secrets_in_layers.txt" 2>/dev/null || true
    local layer_secrets
    layer_secrets=$(wc -l < "${OUT}/04_image/secrets_in_layers.txt" | tr -d ' \n\r')
    if [[ "${layer_secrets}" -gt 0 ]]; then
        ioc "HOCH" "Image-Secrets" "${layer_secrets} potenzielle Secrets in Image-Layern"
    fi

    # Verdächtige RUN-Befehle
    grep -iE '(wget|curl|chmod \+x|base64|nc |ncat|\.sh|python -c|perl -e|ruby -e|/dev/shm|pastebin|raw\.github)' \
        "${OUT}/04_image/docker_history_full.txt" \
        > "${OUT}/04_image/suspicious_layer_commands.txt" 2>/dev/null || true
    local susp_layers
    susp_layers=$(wc -l < "${OUT}/04_image/suspicious_layer_commands.txt" | tr -d ' \n\r')
    if [[ "${susp_layers}" -gt 0 ]]; then
        ioc "MITTEL" "Image-History" "${susp_layers} verdächtige Befehle in Image-History"
    else
        ok "Keine offensichtlich verdächtigen Layer-Befehle"
    fi

    # Image ENV-Variablen
    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${IMAGE_REF}" \
        2>/dev/null > "${OUT}/04_image/image_env_vars.txt" \
        || docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${IMAGE_ID}" \
        2>/dev/null > "${OUT}/04_image/image_env_vars.txt" || true

    # Image Labels
    docker inspect --format '{{json .Config.Labels}}' "${IMAGE_REF}" \
        2>/dev/null | jq '.' > "${OUT}/04_image/image_labels.json" \
        || echo "{}" > "${OUT}/04_image/image_labels.json"

    # Layer-Zusammenfassung
    local layer_count
    layer_count=$(grep -c '^\(sha256:\|<missing>\)' "${OUT}/04_image/docker_history_full.txt" 2>/dev/null || true)
    layer_count="${layer_count:-0}"
    cat > "${OUT}/04_image/layer_summary.txt" << EOF
Image: ${IMAGE_REF}
Image-ID: ${IMAGE_ID}
Layer-Anzahl: ${layer_count}
Verdächtige Befehle: ${susp_layers}
Secrets in Layern: ${layer_secrets}
Analyse-Zeitstempel: ${TS_HUMAN}
EOF
    ok "Image-Analyse abgeschlossen (${layer_count} Layer)"

    _log "Phase 4 abgeschlossen"
}

################################################################################
# PHASE 5: LOGS & IOC-SCAN
################################################################################

phase_logs() {
    step "Phase 5: Log-Analyse & IOC-Scan"

    # Docker-Logs
    docker logs "${CONTAINER_ID}" > "${OUT}/05_logs/docker_logs.txt" 2>&1 || true
    local log_lines
    log_lines=$(wc -l < "${OUT}/05_logs/docker_logs.txt" | tr -d ' \n\r')
    ok "${log_lines} Zeilen Docker-Logs gespeichert"

    # IOC-Scan: Parallele Arrays (Bash 3.2 kompatibel)
    local CATS=()
    local PATS=()

    CATS+=("Web-Exploit")
    PATS+=("(sqlmap|burpsuite|nikto|dirb|gobuster|wfuzz|hydra|medusa|john|hashcat|mimikatz|meterpreter|metasploit)")

    CATS+=("Reverse-Shell")
    PATS+=("(bash -i.*>&|/dev/tcp|nc -e|ncat -e|python.*socket.*connect|perl.*socket|ruby.*socket|socat.*exec)")

    CATS+=("Privilege-Escalation")
    PATS+=("(sudo -l|\/etc\/sudoers|chmod \+s|chown root|pkexec|dirty.cow|cve-20)")

    CATS+=("Reconnaissance")
    PATS+=("(nmap|masscan|zmap|netdiscover|arp-scan|ping.*sweep|traceroute)")

    CATS+=("Crypto-Mining")
    PATS+=("(xmrig|minerd|cpuminer|stratum\+tcp|mining|coinhive|cryptonight|monero)")

    CATS+=("Data-Exfiltration")
    PATS+=("(curl.*upload|wget.*post|ftp.*put|rsync.*remote|scp -P|tar.*\|.*nc|base64.*\|.*curl)")

    CATS+=("Persistence")
    PATS+=("(crontab -e|\/etc\/cron|\.bash_profile|\.bashrc|\.profile|rc\.local|systemctl enable|service.*enable)")

    CATS+=("C2-Kommunikation")
    PATS+=("(dns.tunnel|iodine|dnscat|icmp.tunnel|ptunnel|stunnel|proxychains)")

    CATS+=("Lateral-Movement")
    PATS+=("(ssh-keygen|ssh-keyscan|authorized_keys|known_hosts|puppet|ansible|chef|salt)")

    local ioc_total=0
    local i=0
    while [[ "${i}" -lt "${#CATS[@]}" ]]; do
        local cat_name="${CATS[${i}]}"
        local pattern="${PATS[${i}]}"
        local hits
        hits=$(grep -icE "${pattern}" "${OUT}/05_logs/docker_logs.txt" 2>/dev/null || true)
        if [[ "${hits}" -gt 0 ]]; then
            ioc "MITTEL" "Log-IOC:${cat_name}" "${hits} Treffer für Pattern '${cat_name}'"
            ioc_total=$((ioc_total + hits))
        fi
        i=$((i + 1))
    done

    if [[ "${ioc_total}" -eq 0 ]]; then
        ok "Keine IOC-Patterns in Docker-Logs gefunden"
    else
        warn "${ioc_total} IOC-Treffer in Docker-Logs"
    fi

    # Timeline erstellen
    {
        echo "=== FORENSIK TIMELINE ==="
        echo "Container erstellt: ${CREATED}"
        echo "Analyse gestartet: ${TS_HUMAN}"
        echo ""
        echo "=== LETZTE LOG-EINTRÄGE ==="
        tail -50 "${OUT}/05_logs/docker_logs.txt" 2>/dev/null || true
    } > "${OUT}/05_logs/timeline.txt"

    # System-Logs (Host)
    {
        echo "=== HOST SYSTEM LOGS ==="
        if [[ -f /var/log/docker.log ]]; then
            grep "${CONTAINER_ID:0:12}" /var/log/docker.log 2>/dev/null | tail -50 || true
        elif command -v journalctl &>/dev/null; then
            journalctl -u docker --since "1 hour ago" --no-pager 2>/dev/null | tail -50 || true
        else
            echo "(keine Host-System-Logs verfügbar)"
        fi
    } > "${OUT}/05_logs/system_logs.txt"

    ok "Log-Analyse abgeschlossen"
    _log "Phase 5 abgeschlossen"
}

################################################################################
# PHASE 6: NETZWERK
################################################################################

phase_network() {
    step "Phase 6: Netzwerk-Analyse"

    # Netzwerk-Settings
    docker inspect --format '{{json .NetworkSettings}}' "${CONTAINER_ID}" \
        2>/dev/null | jq '.' > "${OUT}/06_network/network_settings.json" || echo "{}" > "${OUT}/06_network/network_settings.json"

    # Port-Mappings
    docker port "${CONTAINER_ID}" 2>/dev/null > "${OUT}/06_network/port_mappings.txt" || \
        echo "(keine Port-Mappings)" > "${OUT}/06_network/port_mappings.txt"
    local port_count
    port_count=$(grep -c ':' "${OUT}/06_network/port_mappings.txt" 2>/dev/null || true)
    port_count="${port_count:-0}"
    ok "${port_count} Port-Mappings"

    # Verbundene Netzwerke
    docker inspect --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' \
        "${CONTAINER_ID}" 2>/dev/null > "${OUT}/06_network/connected_networks.txt" || true

    local net_count
    net_count=$(wc -l < "${OUT}/06_network/connected_networks.txt" | tr -d ' \n\r')
    ok "${net_count} verbundene Netzwerke"

    if [[ "${RUNNING}" == "true" ]]; then
        # Routing und iptables
        run_in ip route 2>/dev/null >> "${OUT}/06_network/routing.txt" || true
        run_in iptables -L -n 2>/dev/null > "${OUT}/06_network/iptables.txt" || \
            echo "(iptables nicht verfügbar)" > "${OUT}/06_network/iptables.txt"
        run_in cat /etc/resolv.conf 2>/dev/null > "${OUT}/06_network/resolv.conf" || true
    else
        skip "Routing/iptables (Container gestoppt)"
        for f in iptables.txt resolv.conf; do
            echo "(Container gestoppt)" > "${OUT}/06_network/${f}"
        done
    fi

    # Alle Docker-Netzwerke detailliert
    docker network ls -q 2>/dev/null | while read -r netid; do
        docker network inspect "${netid}" 2>/dev/null || true
    done | jq -s 'add // []' > "${OUT}/06_network/docker_networks_detail.json" || true

    # Sicherheits-Check: Exposed ports
    if grep -q '0\.0\.0\.0' "${OUT}/06_network/port_mappings.txt" 2>/dev/null; then
        warn "Ports an 0.0.0.0 (alle Interfaces) gebunden"
    fi

    ok "Netzwerk-Analyse abgeschlossen"
    _log "Phase 6 abgeschlossen"
}

################################################################################
# PHASE 7: BEWEISE SICHERN
################################################################################

phase_evidence() {
    step "Phase 7: Beweissicherung (docker commit, save, export)"

    # docker commit
    local commit_out
    if commit_out=$(docker commit \
        --message "Forensische Sicherung: Case ${CASE_ID}, Analyst: ${ANALYST}, Zeit: ${TS_HUMAN}" --no-pause \
        "${CONTAINER_ID}" "${FORENSIC_IMG}" 2>&1); then
        ok "docker commit erstellt: ${FORENSIC_IMG}"
        echo "${commit_out}" > "${OUT}/07_evidence/docker_commit.log"
        docker inspect "${FORENSIC_IMG}" 2>/dev/null \
          | jq '.' > "${OUT}/07_evidence/committed_image_inspect.json" || true
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] docker commit erstellt: ${FORENSIC_IMG}" >> "${COC}"
    else
        warn "docker commit fehlgeschlagen: ${commit_out}"
        echo "${commit_out}" > "${OUT}/07_evidence/docker_commit.log"
    fi

    if [[ "${SKIP_EXPORT}" -eq 0 ]]; then
        # docker save (forensisches Image)
        echo -n "  Speichere forensisches Image (docker save)..."
        local forensic_tar="${OUT}/07_evidence/forensic_image.tar.gz"
        if docker save "${FORENSIC_IMG}" 2>/dev/null | gzip > "${forensic_tar}"; then
            ok " forensic_image.tar.gz erstellt"
            hash_evidence "${forensic_tar}"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] forensic_image.tar.gz erstellt" >> "${COC}"
        else
            warn "docker save fehlgeschlagen"
        fi

        # docker export (Dateisystem)
        echo -n "  Exportiere Dateisystem (docker export)..."
        local fs_tar="${OUT}/07_evidence/filesystem_export.tar.gz"
        if docker export "${CONTAINER_ID}" 2>/dev/null | gzip > "${fs_tar}"; then
            ok " filesystem_export.tar.gz erstellt"
            hash_evidence "${fs_tar}"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] filesystem_export.tar.gz erstellt" >> "${COC}"
        else
            warn "docker export fehlgeschlagen"
        fi

        # Original-Image speichern
        echo -n "  Speichere Original-Image..."
        local orig_tar="${OUT}/07_evidence/original_image.tar.gz"
        if docker save "${IMAGE_REF}" 2>/dev/null | gzip > "${orig_tar}" \
            || docker save "${IMAGE_ID}" 2>/dev/null | gzip > "${orig_tar}"; then
            ok " original_image.tar.gz erstellt"
            hash_evidence "${orig_tar}"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] original_image.tar.gz erstellt" >> "${COC}"
        else
            warn "Original-Image save fehlgeschlagen"
        fi
    else
        skip "Image-Export (--no-export gesetzt)"
        echo "(Export übersprungen via --no-export)" > "${OUT}/07_evidence/forensic_image.tar.gz" || true
        echo "(Export übersprungen via --no-export)" > "${OUT}/07_evidence/filesystem_export.tar.gz" || true
        echo "(Export übersprungen via --no-export)" > "${OUT}/07_evidence/original_image.tar.gz" || true
    fi

    # SHA256 für alle txt/json-Dateien
    find "${OUT}" -type f \( -name '*.txt' -o -name '*.json' -o -name '*.md' -o -name '*.log' \) \
        ! -name 'SHA256_MANIFEST.txt' 2>/dev/null \
        | sort \
        | while read -r f; do
            hash_evidence "${f}"
          done

    local hash_count
    hash_count=$(wc -l < "${SHA256_MANIFEST}" | tr -d ' \n\r')
    ok "${hash_count} Dateien gehasht (SHA256)"

    # Chain of Custody abschließen
    {
        echo ""
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Beweissicherung abgeschlossen"
        echo "SHA256-Manifest: ${SHA256_MANIFEST}"
        echo "Anzahl Einträge: ${hash_count}"
    } >> "${COC}"

    _log "Phase 7 abgeschlossen"
}

################################################################################
# PHASE 8: REPORT
################################################################################

phase_report() {
    step "Phase 8: Bericht & Zusammenfassung"

    local ioc_count
    ioc_count=$(wc -l < "${IOC_FILE}" | tr -d ' \n\r')

    local kritisch_count
    kritisch_count=$(grep -c '^\[KRITISCH\]' "${IOC_FILE}" 2>/dev/null || true)
    kritisch_count="${kritisch_count:-0}"
    local hoch_count
    hoch_count=$(grep -c '^\[HOCH\]' "${IOC_FILE}" 2>/dev/null || true)
    hoch_count="${hoch_count:-0}"
    local mittel_count
    mittel_count=$(grep -c '^\[MITTEL\]' "${IOC_FILE}" 2>/dev/null || true)
    mittel_count="${mittel_count:-0}"
    local niedrig_count
    niedrig_count=$(grep -c '^\[NIEDRIG\]' "${IOC_FILE}" 2>/dev/null || true)
    niedrig_count="${niedrig_count:-0}"

    # Risiko-Level bestimmen
    local risk_level="NIEDRIG"
    local risk_color="${GRN}"
    if [[ "${kritisch_count}" -gt 0 ]]; then
        risk_level="KRITISCH"
        risk_color="${RED}"
    elif [[ "${hoch_count}" -gt 2 ]]; then
        risk_level="HOCH"
        risk_color="${RED}"
    elif [[ "${hoch_count}" -gt 0 || "${mittel_count}" -gt 3 ]]; then
        risk_level="MITTEL"
        risk_color="${YLW}"
    fi

    local end_epoch
    end_epoch=$(date +%s)
    local duration=$((end_epoch - START_EPOCH))

    # 00_ZUSAMMENFASSUNG.md
    cat > "${SUMMARY}" << EOF
# Docker Forensik — Zusammenfassung

## Fall-Informationen

| Feld | Wert |
|------|------|
| Fall-ID | \`${CASE_ID}\` |
| Container-Name | \`${CONTAINER_NAME}\` |
| Container-ID | \`${CONTAINER_ID:0:12}\` |
| Image | \`${IMAGE_REF}\` |
| Status | \`${STATUS}\` |
| Analyst | ${ANALYST} |
| Analyse-Zeitpunkt | ${TS_HUMAN} |
| Analyse-Dauer | ${duration} Sekunden |
| Ausgabe-Verzeichnis | \`${OUT}\` |

## Risiko-Bewertung

**RISIKO-LEVEL: ${risk_level}**

| Schweregrad | Anzahl |
|-------------|--------|
| KRITISCH | ${kritisch_count} |
| HOCH | ${hoch_count} |
| MITTEL | ${mittel_count} |
| NIEDRIG | ${niedrig_count} |
| **Gesamt** | **${ioc_count}** |

## Statistiken

| Metrik | Wert |
|--------|------|
| Dateisystem-Änderungen (docker diff) | ${DIFF_COUNT} |
| IOC-Befunde gesamt | ${ioc_count} |
| Forensisches Image | \`${FORENSIC_IMG}\` |
| Export übersprungen | $([ "${SKIP_EXPORT}" -eq 1 ] && echo "Ja" || echo "Nein") |

## IOC-Befunde

EOF

    if [[ "${ioc_count}" -gt 0 ]]; then
        echo '```' >> "${SUMMARY}"
        cat "${IOC_FILE}" >> "${SUMMARY}"
        echo '```' >> "${SUMMARY}"
    else
        echo "_Keine IOC-Befunde gefunden._" >> "${SUMMARY}"
    fi

    cat >> "${SUMMARY}" << EOF

## Verzeichnisstruktur

\`\`\`
${OUT}/
├── 00_ZUSAMMENFASSUNG.md      ← Diese Datei
├── 01_metadata/               ← Container-Metadaten, Inventar
├── 02_volatile/               ← ENV-Vars, Prozesse, Verbindungen
├── 03_filesystem/             ← docker diff, SUID, Webshells, History
├── 04_image/                  ← Docker-History, Layer-Analyse
├── 05_logs/                   ← Docker-Logs, IOC-Scan, Timeline
├── 06_network/                ← Port-Mappings, Netzwerk-Settings
├── 07_evidence/               ← Beweise, SHA256-Manifest, Chain of Custody
├── 08_report/                 ← Forensik-Bericht
├── 09_ramdump/                ← Memory-Maps, RAM-Dump, Strings, CRIU-Checkpoint
└── AUDIT.log                  ← Vollständiges Audit-Log
\`\`\`

## Empfehlungen

EOF

    if [[ "${kritisch_count}" -gt 0 ]]; then
        echo "- **SOFORTMASSNAHME**: Kritische Befunde erfordern unmittelbare Incident-Response" >> "${SUMMARY}"
        echo "- Container sofort isolieren und Sicherheitsteam informieren" >> "${SUMMARY}"
    fi
    if [[ "${hoch_count}" -gt 0 ]]; then
        echo "- Hochpriorisierte Befunde zeitnah untersuchen" >> "${SUMMARY}"
    fi
    echo "- SHA256-Manifest verifizieren vor Weiterverarbeitung der Beweise" >> "${SUMMARY}"
    echo "- Chain-of-Custody-Dokument für Beweiskette aufbewahren" >> "${SUMMARY}"
    echo "" >> "${SUMMARY}"
    echo "---" >> "${SUMMARY}"
    echo "_Erstellt von forensik.sh v1.0 | ${TS_HUMAN} | Analyst: ${ANALYST}_" >> "${SUMMARY}"

    ok "00_ZUSAMMENFASSUNG.md erstellt"

    # 08_report/forensic_report.txt
    cat > "${OUT}/08_report/forensic_report.txt" << EOF
================================================================================
DOCKER FORENSIK BERICHT
================================================================================
Fall-ID:            ${CASE_ID}
Container:          ${CONTAINER_NAME} (${CONTAINER_ID:0:12})
Image:              ${IMAGE_REF}
Status:             ${STATUS}
Analyst:            ${ANALYST}
Zeitstempel:        ${TS_HUMAN}
Analyse-Dauer:      ${duration} Sekunden
================================================================================

RISIKO-LEVEL: ${risk_level}

IOC-ZUSAMMENFASSUNG:
  KRITISCH:  ${kritisch_count}
  HOCH:      ${hoch_count}
  MITTEL:    ${mittel_count}
  NIEDRIG:   ${niedrig_count}
  GESAMT:    ${ioc_count}

STATISTIKEN:
  Dateisystem-Änderungen: ${DIFF_COUNT}
  Forensisches Image:     ${FORENSIC_IMG}

IOC-DETAILS:
$(cat "${IOC_FILE}" 2>/dev/null || echo "  (keine Befunde)")

================================================================================
AUSGABE-VERZEICHNIS: ${OUT}
================================================================================
EOF

    ok "forensic_report.txt erstellt"

    # Finale Ausgabe im Terminal
    echo ""
    echo -e "${BOLD}${CYN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${CYN}║              ANALYSE ABGESCHLOSSEN                           ║${NC}"
    echo -e "${BOLD}${CYN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Fall-ID:     ${BOLD}${CASE_ID}${NC}"
    echo -e "  Container:   ${BOLD}${CONTAINER_NAME}${NC}"
    echo -e "  Status:      ${BOLD}${STATUS}${NC}"
    echo -e "  Dauer:       ${BOLD}${duration}s${NC}"
    echo ""
    echo -e "  ${BOLD}RISIKO-LEVEL: ${risk_color}${risk_level}${NC}"
    echo ""
    echo -e "  IOC-Befunde:"
    echo -e "    ${RED}KRITISCH: ${kritisch_count}${NC}"
    echo -e "    ${RED}HOCH:     ${hoch_count}${NC}"
    echo -e "    ${YLW}MITTEL:   ${mittel_count}${NC}"
    echo -e "    ${GRN}NIEDRIG:  ${niedrig_count}${NC}"
    echo ""
    echo -e "  ${BOLD}Ausgabe-Verzeichnis:${NC}"
    echo -e "  ${BLU}${OUT}${NC}"
    echo ""
    echo -e "  ${BOLD}Schlüsseldateien:${NC}"
    echo -e "  ${DIM}• ${OUT}/00_ZUSAMMENFASSUNG.md${NC}"
    echo -e "  ${DIM}• ${OUT}/05_logs/ioc_findings.txt${NC}"
    echo -e "  ${DIM}• ${OUT}/07_evidence/SHA256_MANIFEST.txt${NC}"
    echo -e "  ${DIM}• ${OUT}/07_evidence/chain_of_custody.txt${NC}"
    echo -e "  ${DIM}• ${OUT}/08_report/forensic_report.txt${NC}"
    echo ""

    _log "Phase 8 abgeschlossen — Risiko: ${risk_level}, IOCs: ${ioc_count}"
}

################################################################################
# PHASE 9: RAM-DUMP
################################################################################

phase_ramdump() {
    step "Phase 9: RAM-Dump & Arbeitsspeicher-Analyse"

    if [[ "${RUNNING}" != "true" ]]; then
        skip "RAM-Dump (Container gestoppt)"
        echo "(Container gestoppt — kein Arbeitsspeicher verfügbar)" > "${OUT}/09_ramdump/README.txt"
        _log "Phase 9 übersprungen (Container gestoppt)"
        return
    fi

    # Haupt-PID des Containers auf dem Host ermitteln
    local main_pid
    main_pid=$(docker inspect --format '{{.State.Pid}}' "${CONTAINER_ID}" 2>/dev/null || echo "0")
    main_pid="${main_pid:-0}"

    {
        echo "Container-Haupt-PID (Host): ${main_pid}"
        echo "Analyse-Zeitstempel:        ${TS_HUMAN}"
        echo "Methoden: /proc maps, dd memory-dump, environ-scan, CRIU-Checkpoint"
    } > "${OUT}/09_ramdump/README.txt"

    ok "Container-PID auf Host: ${main_pid}"

    # --- 1. Memory-Maps aller Prozesse ---
    run_in sh -c '
        for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do
            cmd=$(cat /proc/${pid}/cmdline 2>/dev/null | tr "\0" " " | cut -c1-80)
            echo "=== PID ${pid}: ${cmd} ==="
            cat /proc/${pid}/maps 2>/dev/null || true
            echo ""
        done
    ' > "${OUT}/09_ramdump/proc_maps_all.txt" 2>/dev/null || true
    ok "Memory-Maps aller Prozesse gesichert"

    # --- 2. smaps (detaillierter Speicher-Breakdown je Segment) ---
    run_in sh -c '
        for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do
            echo "=== PID ${pid} ==="
            cat /proc/${pid}/smaps 2>/dev/null || true
        done
    ' > "${OUT}/09_ramdump/proc_smaps.txt" 2>/dev/null || true

    # --- 3. Environ aller Prozesse (Secret-Suche im laufenden RAM) ---
    run_in sh -c '
        for pid in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do
            echo "=== PID ${pid} ==="
            cat /proc/${pid}/environ 2>/dev/null | tr "\0" "\n" || true
            echo ""
        done
    ' > "${OUT}/09_ramdump/proc_environ.txt" 2>/dev/null || true


    # --- 4. Binärer Memory-Dump via dd (lesbare Segmente, PID 1) ---
    local dump_file="${OUT}/09_ramdump/memory_dump_pid1.bin"

    run_in sh -c '
        pid=1
        while IFS= read -r line; do
            range=$(echo "${line}" | awk "{print \$1}")
            perms=$(echo "${line}" | awk "{print \$2}")
            case "${perms}" in r*) ;; *) continue ;; esac
            case "${line}" in */dev/*|*/run/*|*vsyscall*|*vvar*|*vdso*) continue ;; esac
            start_hex=$(echo "${range}" | cut -d- -f1)
            end_hex=$(echo "${range}" | cut -d- -f2)
            start_dec=$(( 16#${start_hex} )) 2>/dev/null || continue
            end_dec=$(( 16#${end_hex} )) 2>/dev/null || continue
            size=$(( end_dec - start_dec ))
            [ "${size}" -le 0 ] && continue
            [ "${size}" -gt 67108864 ] && continue
            skip_blk=$(( start_dec / 4096 ))
            count_blk=$(( (size + 4095) / 4096 ))
            [ "${count_blk}" -le 0 ] && continue
            dd if=/proc/${pid}/mem bs=4096 skip=${skip_blk} count=${count_blk} 2>/dev/null || true
        done < /proc/${pid}/maps
    ' > "${dump_file}" 2>/dev/null || true

    local dump_size
    dump_size=$(wc -c < "${dump_file}" 2>/dev/null | tr -d ' \n\r' || echo "0")
    dump_size="${dump_size:-0}"

    if [[ "${dump_size}" -gt 0 ]]; then
        local dump_kb=$(( dump_size / 1024 ))
        ok "Memory-Dump erstellt: ${dump_kb} KB"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Memory-Dump PID 1: ${dump_kb} KB" >> "${COC}"

        # Strings extrahieren
        strings "${dump_file}" > "${OUT}/09_ramdump/strings_memory.txt" 2>/dev/null || true
        local str_count
        str_count=$(wc -l < "${OUT}/09_ramdump/strings_memory.txt" | tr -d ' \n\r')
        ok "${str_count} Strings aus Memory extrahiert"

        # Secrets in extrahierten Strings suchen
        find_secrets < "${OUT}/09_ramdump/strings_memory.txt" \
            > "${OUT}/09_ramdump/strings_secrets.txt" 2>/dev/null || true
        local mem_sec
        mem_sec=$(wc -l < "${OUT}/09_ramdump/strings_secrets.txt" | tr -d ' \n\r')
        mem_sec="${mem_sec:-0}"
        if [[ "${mem_sec}" -gt 0 ]]; then
            ioc "KRITISCH" "RAM-Secrets" "${mem_sec} potenzielle Secrets im Arbeitsspeicher (strings)"
        else
            ok "Keine Secrets im Arbeitsspeicher gefunden"
        fi

        hash_evidence "${dump_file}"
    else
        warn "Memory-Dump leer (SYS_PTRACE fehlt oder macOS/Docker-VM — /proc/mem nicht direkt zugänglich)"
        echo "(nicht verfügbar — SYS_PTRACE-Capability oder Linux-Host erforderlich)" \
            > "${OUT}/09_ramdump/memory_dump_pid1.bin.info"
        rm -f "${dump_file}"
    fi

    # --- 5. CRIU-Checkpoint (docker checkpoint — experimentell) ---
    local ckpt_name="forensic-${TIMESTAMP}"
    if docker checkpoint create --help &>/dev/null 2>&1; then
        echo -n "  Versuche CRIU-Checkpoint (docker checkpoint create --leave-running)..."
        if docker checkpoint create --leave-running "${CONTAINER_ID}" "${ckpt_name}" 2>/dev/null; then
            ok "CRIU-Checkpoint erstellt: ${ckpt_name}"
            echo "${ckpt_name}" > "${OUT}/09_ramdump/criu_checkpoint_name.txt"
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] CRIU-Checkpoint: ${ckpt_name}" >> "${COC}"
        else
            warn "CRIU-Checkpoint fehlgeschlagen (--experimental in dockerd erforderlich)"
        fi
    else
        skip "CRIU-Checkpoint (docker checkpoint nicht verfügbar)"
    fi

    _log "Phase 9 abgeschlossen"
}

################################################################################
# VOLLSTÄNDIGE ANALYSE
################################################################################

run_full_analysis() {
    local container_input="$1"
    local case_id="${2:-}"
    local skip_export="${3:-0}"

    init_analysis "${container_input}" "${case_id}" "${skip_export}"

    echo ""
    echo -e "${BOLD}${CYN}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  Starte forensische Analyse${NC}"
    echo -e "  Container:  ${BOLD}${CONTAINER_NAME}${NC}"
    echo -e "  Fall-ID:    ${BOLD}${CASE_ID}${NC}"
    echo -e "  Export:     $([ "${SKIP_EXPORT}" -eq 1 ] && echo "${YLW}Nein${NC}" || echo "${GRN}Ja${NC}")"
    echo -e "  Ausgabe:    ${BLU}${OUT}${NC}"
    echo -e "${BOLD}${CYN}════════════════════════════════════════════════════════════════${NC}"
    echo ""

    phase_metadata
    phase_volatile
    phase_ramdump
    phase_filesystem
    phase_image
    phase_logs
    phase_network
    phase_evidence
    phase_report
}

################################################################################
# MENÜ-HILFSFUNKTIONEN
################################################################################

list_containers() {
    echo -e "${BOLD}  Nr  Name                            ID            Status${NC}"
    echo -e "  ────────────────────────────────────────────────────────"
    local i=1
    docker ps -a --format '{{.Names}}\t{{.ID}}\t{{.Status}}' 2>/dev/null | while IFS=$'\t' read -r name cid status; do
        printf "  [%d] %-32s %-14s %s\n" "${i}" "${name}" "${cid}" "${status}"
        i=$((i + 1))
    done
}

get_container_by_number() {
    local num="$1"
    docker ps -a --format '{{.Names}}' 2>/dev/null | sed -n "${num}p"
}

count_containers() {
    docker ps -a --format '{{.Names}}' 2>/dev/null | wc -l | tr -d ' \n\r'
}

################################################################################
# MENÜ: ANALYSE STARTEN
################################################################################

menu_start_analysis() {
    while true; do
        show_banner
        echo -e "${BOLD}  [ Analyse starten ]${NC}"
        echo ""

        # Container anzeigen
        local total
        total=$(count_containers)
        if [[ "${total}" -eq 0 ]]; then
            echo -e "${YLW}  Keine Docker-Container gefunden.${NC}"
            press_enter
            return
        fi

        list_containers
        echo ""
        echo -e "  Nummer eingeben ODER Container-ID/Name direkt eingeben"
        echo -e "  [b] Zurück zum Hauptmenü"
        echo ""
        echo -n "  Auswahl: "
        read -r container_input

        case "${container_input}" in
            b|B|q|Q) return ;;
            "") continue ;;
        esac

        # Wenn Nummer, dann umwandeln
        local selected_container="${container_input}"
        if echo "${container_input}" | grep -qE '^[0-9]+$'; then
            local num="${container_input}"
            if [[ "${num}" -ge 1 && "${num}" -le "${total}" ]]; then
                selected_container=$(get_container_by_number "${num}")
            fi
        fi

        if [[ -z "${selected_container}" ]]; then
            echo -e "${RED}  Fehler: Ungültige Auswahl.${NC}"
            press_enter
            continue
        fi

        if ! docker inspect "${selected_container}" &>/dev/null; then
            echo -e "${RED}  Fehler: Container '${selected_container}' nicht gefunden.${NC}"
            press_enter
            continue
        fi

        # Fall-ID
        echo ""
        echo -n "  Fall-ID eingeben (Enter = automatisch generieren): "
        read -r input_case_id

        # Export-Option
        echo ""
        echo -n "  Image-Export durchführen? (docker save/export) [J/n]: "
        read -r export_choice
        local do_skip_export=0
        case "${export_choice}" in
            n|N) do_skip_export=1 ;;
        esac

        # Bestätigung
        show_banner
        echo -e "${BOLD}  [ Analyse-Konfiguration ]${NC}"
        echo ""
        echo -e "  Container:    ${BOLD}${selected_container}${NC}"

        local cname cstatus
        cname=$(docker inspect --format '{{.Name}}' "${selected_container}" | sed 's|^/||')
        cstatus=$(docker inspect --format '{{.State.Status}}' "${selected_container}")

        echo -e "  Name:         ${cname}"
        echo -e "  Status:       ${cstatus}"
        echo -e "  Fall-ID:      ${input_case_id:-automatisch generieren}"
        echo -e "  Image-Export: $([ "${do_skip_export}" -eq 1 ] && echo "${YLW}Nein${NC}" || echo "${GRN}Ja${NC}")"
        echo ""
        echo -e "${YLW}  Hinweis: Große Images können viel Zeit und Speicherplatz benötigen!${NC}"
        echo ""
        echo -n "  Analyse jetzt starten? [J/n]: "
        read -r confirm

        case "${confirm}" in
            n|N) continue ;;
        esac

        echo ""
        run_full_analysis "${selected_container}" "${input_case_id}" "${do_skip_export}"
        press_enter
        return
    done
}

################################################################################
# MENÜ: CONTAINER ANZEIGEN
################################################################################

menu_show_containers() {
    show_banner
    echo -e "${BOLD}  [ Alle Docker-Container ]${NC}"
    echo ""

    local total
    total=$(count_containers)
    if [[ "${total}" -eq 0 ]]; then
        echo -e "${YLW}  Keine Docker-Container gefunden.${NC}"
    else
        docker ps -a --format 'table {{.Names}}\t{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true
        echo ""
        echo -e "  ${DIM}Gesamt: ${total} Container${NC}"
    fi

    echo ""
    press_enter
}

################################################################################
# MENÜ: LETZTE ERGEBNISSE
################################################################################

menu_last_results() {
    while true; do
        show_banner
        echo -e "${BOLD}  [ Letzte Forensik-Ergebnisse ]${NC}"
        echo ""

        if [[ ! -d "${RESULTS_BASE}" ]]; then
            echo -e "${YLW}  Kein forensic-results/ Verzeichnis gefunden.${NC}"
            press_enter
            return
        fi

        # Alle Unterordner, neueste zuerst
        local results=()
        while IFS= read -r -d '' dir; do
            results+=("${dir}")
        done < <(find "${RESULTS_BASE}" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null \
            | sort -rz)

        if [[ "${#results[@]}" -eq 0 ]]; then
            echo -e "${YLW}  Noch keine Analyseergebnisse vorhanden.${NC}"
            press_enter
            return
        fi

        local i=1
        for dir in "${results[@]}"; do
            local dirname
            dirname=$(basename "${dir}")
            local summary_exists=""
            [[ -f "${dir}/00_ZUSAMMENFASSUNG.md" ]] && summary_exists=" ${GRN}[Zusammenfassung OK]${NC}"
            printf "  ${BOLD}[%d]${NC} %-50s%s\n" "${i}" "${dirname}" "${summary_exists}"
            i=$((i + 1))
        done

        echo ""
        echo -e "  [b] Zurück"
        echo ""
        echo -n "  Auswahl (Nummer): "
        read -r choice

        case "${choice}" in
            b|B|q|Q) return ;;
            "") continue ;;
        esac

        if ! echo "${choice}" | grep -qE '^[0-9]+$'; then
            continue
        fi

        local idx=$((choice - 1))
        if [[ "${idx}" -lt 0 || "${idx}" -ge "${#results[@]}" ]]; then
            echo -e "${RED}  Ungültige Auswahl.${NC}"
            press_enter
            continue
        fi

        local selected_dir="${results[${idx}]}"
        local summary_file="${selected_dir}/00_ZUSAMMENFASSUNG.md"

        if [[ -f "${summary_file}" ]]; then
            echo ""
            echo -e "${BOLD}${CYN}═══════════════════════════════════════════════════${NC}"
            cat "${summary_file}"
            echo -e "${BOLD}${CYN}═══════════════════════════════════════════════════${NC}"
            echo ""
            echo -e "  ${DIM}Vollständiger Pfad: ${selected_dir}${NC}"
        else
            echo -e "${YLW}  Keine 00_ZUSAMMENFASSUNG.md in ${selected_dir}${NC}"
        fi

        press_enter
    done
}

################################################################################
# MENÜ: DEMO-UMGEBUNG
################################################################################

menu_demo() {
    while true; do
        show_banner
        echo -e "${BOLD}  [ Demo-Umgebung ]${NC}"
        echo ""

        # Status prüfen
        if [[ ! -d "${DEMO_DIR}" ]]; then
            echo -e "${YLW}  demo-target/ Verzeichnis nicht gefunden.${NC}"
            echo -e "  Erwartet: ${DEMO_DIR}"
            press_enter
            return
        fi

        local compose_file=""
        for f in "${DEMO_DIR}/docker-compose.yml" "${DEMO_DIR}/docker-compose.yaml"; do
            [[ -f "${f}" ]] && compose_file="${f}" && break
        done

        if [[ -z "${compose_file}" ]]; then
            echo -e "${YLW}  Keine docker-compose.yml in ${DEMO_DIR} gefunden.${NC}"
            press_enter
            return
        fi

        # Status ermitteln
        local running_containers=0
        running_containers=$(cd "${DEMO_DIR}" && docker compose ps -q 2>/dev/null | wc -l | tr -d ' \n\r') || running_containers=0

        if [[ "${running_containers}" -gt 0 ]]; then
            echo -e "  Status: ${GRN}${BOLD}AKTIV${NC} (${running_containers} Container laufen)"
            echo ""
            cd "${DEMO_DIR}" && docker compose ps 2>/dev/null && cd "${SCRIPT_DIR}" || true
        else
            echo -e "  Status: ${RED}${BOLD}GESTOPPT${NC}"
        fi

        echo ""
        echo -e "  ${BOLD}[1]${NC} Demo starten  (docker compose up -d)"
        echo -e "  ${BOLD}[2]${NC} Demo stoppen  (docker compose down)"
        echo -e "  ${BOLD}[3]${NC} Status anzeigen"
        echo -e "  ${BOLD}[b]${NC} Zurück"
        echo ""
        echo -n "  Auswahl: "
        read -r demo_choice

        case "${demo_choice}" in
            1)
                echo ""
                echo -e "${GRN}  Starte Demo-Umgebung...${NC}"
                (cd "${DEMO_DIR}" && docker compose up -d 2>&1) || true
                press_enter
                ;;
            2)
                echo ""
                echo -e "${YLW}  Stoppe Demo-Umgebung...${NC}"
                (cd "${DEMO_DIR}" && docker compose down 2>&1) || true
                press_enter
                ;;
            3)
                echo ""
                (cd "${DEMO_DIR}" && docker compose ps 2>&1) || true
                press_enter
                ;;
            b|B|q|Q)
                return
                ;;
        esac
    done
}

################################################################################
# HAUPTMENÜ
################################################################################

main_menu() {
    while true; do
        show_banner
        echo -e "  ${BOLD}Hauptmenü${NC}"
        echo ""
        echo -e "  ${BOLD}[1]${NC} Analyse starten"
        echo -e "  ${BOLD}[2]${NC} Container anzeigen"
        echo -e "  ${BOLD}[3]${NC} Letzte Ergebnisse"
        echo -e "  ${BOLD}[4]${NC} Demo-Umgebung"
        echo -e "  ${BOLD}[q]${NC} Beenden"
        echo ""
        echo -n "  Auswahl: "
        read -r main_choice

        case "${main_choice}" in
            1) menu_start_analysis ;;
            2) menu_show_containers ;;
            3) menu_last_results ;;
            4) menu_demo ;;
            q|Q|exit|quit)
                echo ""
                echo -e "  ${DIM}Auf Wiedersehen.${NC}"
                echo ""
                exit 0
                ;;
        esac
    done
}

################################################################################
# ARGUMENT-PARSING & EINSTIEGSPUNKT
################################################################################

parse_direct_args() {
    # ./forensik.sh <container_id> [--case-id ID] [--no-export]
    local container_input="$1"
    shift

    local case_id=""
    local skip_export=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --case-id)
                case_id="${2:-}"
                shift 2
                ;;
            --no-export)
                skip_export=1
                shift
                ;;
            *)
                echo -e "${RED}Unbekannte Option: $1${NC}" >&2
                exit 1
                ;;
        esac
    done

    show_banner
    run_full_analysis "${container_input}" "${case_id}" "${skip_export}"
}

main() {
    if [[ $# -gt 0 ]]; then
        # Direktmodus
        case "$1" in
            --help|-h)
                show_banner
                echo -e "${BOLD}Verwendung:${NC}"
                echo -e "  ./forensik.sh                          — Interaktives Menü"
                echo -e "  ./forensik.sh <container> [Optionen]   — Direkte Analyse"
                echo ""
                echo -e "${BOLD}Optionen:${NC}"
                echo -e "  --case-id <ID>    Fall-ID setzen (Standard: auto)"
                echo -e "  --no-export       docker save/export überspringen"
                echo -e "  --help, -h        Diese Hilfe anzeigen"
                echo ""
                exit 0
                ;;
            *)
                parse_direct_args "$@"
                ;;
        esac
    else
        # Interaktiver Menü-Modus
        main_menu
    fi
}

main "$@"
