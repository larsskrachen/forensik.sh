#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   FORENSIC DEMO TARGET — forensics-target               ║"
echo "║   Kompromittierter Webserver (Simulation)                ║"
echo "╚══════════════════════════════════════════════════════════╝"

# SSH Host-Keys generieren (falls noch nicht vorhanden)
ssh-keygen -A 2>/dev/null || true

# PHP-FPM Socket-Verzeichnis
mkdir -p /run/php

# Forensische Artefakte erstellen
/usr/local/bin/setup-artifacts.sh

# Dienste starten
echo "[entrypoint] Starte Dienste..."
service php8.1-fpm start 2>/dev/null || true
service nginx start       2>/dev/null || true
service cron start        2>/dev/null || true
service ssh start         2>/dev/null || true

echo "[entrypoint] Container läuft — Dienste aktiv: nginx, php-fpm, cron, sshd"

# Container am Leben halten
tail -f /var/log/nginx/access.log /var/log/auth.log 2>/dev/null || \
    while true; do sleep 30; done
