FROM ubuntu:22.04

# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC DEMO TARGET — absichtlich kompromittierter Container
# Dieses Image enthält zahlreiche forensisch relevante Artefakte:
#   • Hardcoded Secrets in Image-Layern
#   • Backdoor-Benutzer
#   • Suspicious SUID-Binaries
#   • Versteckte Dateien und gelöschte Artefakte (noch in Layer-History)
# NUR FÜR FORENSISCHE AUSBILDUNG — nicht produktiv verwenden!
# ─────────────────────────────────────────────────────────────────────────────

ENV DEBIAN_FRONTEND=noninteractive

# ── Layer 1: Basis-Pakete ────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    nginx \
    php8.1-fpm \
    mariadb-client \
    openssh-server \
    cron \
    curl \
    wget \
    netcat-openbsd \
    nmap \
    python3 \
    python3-pip \
    sudo \
    vim \
    net-tools \
    procps \
    tcpdump \
    iproute2 \
    iputils-ping \
    at \
    logrotate \
    && rm -rf /var/lib/apt/lists/*

# ── Layer 2: Legitimer App-Benutzer ─────────────────────────────────────────
RUN useradd -m -s /bin/bash -u 1000 webapp && \
    echo "webapp:W3bApp2024!" | chpasswd && \
    usermod -aG sudo webapp

# ── Layer 3: FORENSIK-ARTEFAKT — Geheimnis "gelöscht" aber in Layer sichtbar
#    docker history / docker save zeigt diesen Layer; rm entfernt nur im Layer darüber
RUN echo "DEPLOY_SECRET=ghp_XxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxXx" > /root/deploy_token.txt && \
    echo "PROD_DB_PASS=Pr0d-MySuperSecr3t-2024!" >> /root/deploy_token.txt && \
    echo "AWS_SECRET_KEY=DUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" >> /root/deploy_token.txt && \
    cat /root/deploy_token.txt && \
    rm /root/deploy_token.txt

# ── Layer 4: SSH-Konfiguration (absichtlich unsicher) ───────────────────────
RUN mkdir /var/run/sshd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "root:toor" | chpasswd

# ── Layer 5: FORENSIK-ARTEFAKT — Backdoor-Benutzer (UID 0, anderer Name) ───
RUN useradd -m -s /bin/bash -u 1337 support && \
    echo "support:Supp0rt#2024" | chpasswd && \
    usermod -aG sudo support && \
    echo "support ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/support && \
    chmod 440 /etc/sudoers.d/support

# ── Layer 6: FORENSIK-ARTEFAKT — SUID-Binary (versteckt) ───────────────────
RUN cp /bin/bash /usr/local/bin/.sysmon && \
    chmod u+s /usr/local/bin/.sysmon && \
    chown root:root /usr/local/bin/.sysmon

# ── Layer 7: FORENSIK-ARTEFAKT — Verdächtige Tools installiert ──────────────
RUN pip3 install --quiet requests paramiko && \
    wget -q https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64 \
         -O /usr/local/bin/.pspy 2>/dev/null || \
    echo "#!/bin/bash" > /usr/local/bin/.pspy && \
    chmod +x /usr/local/bin/.pspy

# ── Layer 8: Applikations-Dateien ───────────────────────────────────────────
COPY config/nginx.conf      /etc/nginx/sites-available/default
COPY config/app.conf        /etc/app/app.conf
COPY config/php-fpm.conf    /etc/php/8.1/fpm/pool.d/www.conf
COPY www/                   /var/www/html/
COPY setup-artifacts.sh     /usr/local/bin/setup-artifacts.sh
COPY entrypoint.sh          /entrypoint.sh
RUN chmod +x /usr/local/bin/setup-artifacts.sh /entrypoint.sh && \
    chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html && \
    # Web-Upload-Verzeichnis absichtlich world-writable
    chmod 777 /var/www/html/upload && \
    mkdir -p /var/log/app /var/log/nginx /var/log/php && \
    touch /var/log/auth.log /var/log/syslog

# ── Layer 9: FORENSIK-ARTEFAKT — Env-Vars mit Secrets ──────────────────────
#    Umgebungsvariablen sind über "docker inspect" sichtbar
ENV DB_HOST=forensics-db \
    DB_PORT=3306 \
    DB_NAME=shopdb \
    DB_USER=root \
    DB_PASSWORD=MySuperSecretDBPass123! \
    API_KEY=sk-prod-a7f3h2k9m1p4r8t6v0x2z5b8n1 \
    JWT_SECRET=eyJhbGciOiJIUzI1NiJ9.ThisIsASecretKeyForJWTSigningNeverExpose \
    STRIPE_SECRET_KEY=sk_live_51HkXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX \
    APP_ENV=production \
    DEBUG=true

# ── SSH-Key (Backdoor) ───────────────────────────────────────────────────────
RUN mkdir -p /root/.ssh && \
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEMO_BACKDOOR_KEY_FORENSIC_DEMO_ONLY attacker@evil.com" \
         > /root/.ssh/authorized_keys && \
    chmod 700 /root/.ssh && \
    chmod 600 /root/.ssh/authorized_keys

EXPOSE 80 22 8080

LABEL maintainer="forensics-demo" \
      version="1.0" \
      description="Forensic Demo Target" \
      forensic.scenario="compromised-webserver" \
      forensic.iocs="backdoor-user,suid-binary,webshell,hardcoded-secrets,suspicious-cron"

ENTRYPOINT ["/entrypoint.sh"]
