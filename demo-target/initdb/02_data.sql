USE shopdb;

-- Benutzer (Passwort-Hashes: bcrypt "password123" für Demo-Zwecke)
INSERT INTO users (username, email, password_hash, role, last_login, ip_address) VALUES
('admin',     'admin@shopsystem.local',   '$2y$10$DEMO_HASH_admin_FORENSIC_ONLY_XXXXX', 'admin',    '2026-04-26 02:11:21', '203.0.113.42'),
('jsmith',    'j.smith@example.com',      '$2y$10$DEMO_HASH_jsmith_FORENSIC_ONLY_XXXX', 'customer', '2026-04-25 14:32:10', '10.0.0.1'),
('m.mueller', 'm.mueller@example.com',    '$2y$10$DEMO_HASH_mmuel_FORENSIC_ONLY_XXXXX', 'customer', '2026-04-24 09:15:44', '10.0.0.2'),
('support',   'support@shopsystem.local', '$2y$10$DEMO_HASH_supp_FORENSIC_ONLY_XXXXXX', 'admin',    '2026-04-26 02:13:47', '10.0.0.99'),
('attacker',  'hax@evil.com',             '$2y$10$DEMO_HASH_attack_FORENSIC_ONLY_XXXX', 'customer', '2026-04-26 02:14:01', '203.0.113.42');

-- Bestellungen
INSERT INTO orders (user_id, total, status, created_at) VALUES
(2, 149.99, 'paid',    '2026-04-20 10:32:11'),
(3,  89.50, 'shipped', '2026-04-21 14:15:00'),
(2, 299.00, 'pending', '2026-04-25 09:44:22'),
(5,   0.01, 'pending', '2026-04-26 02:14:55');  -- Attacker-Bestellung (Test)

-- Zahlungsdaten (FORENSIK-ARTEFAKT: CC im Klartext)
INSERT INTO payment_methods (user_id, card_number, card_holder, expiry, cvv) VALUES
(2, '4111-1111-1111-1111', 'John Smith',    '12/28', '123'),
(3, '5500-0000-0000-0004', 'Maria Mueller', '06/27', '456'),
(4, '4000-0000-0000-0002', 'Support User',  '09/26', '789');

-- Audit-Log (zeigt Angriffs-Timeline)
INSERT INTO audit_log (timestamp, user_id, action, target, ip_address, user_agent, status) VALUES
('2026-04-26 02:11:14', NULL,  'login_attempt', 'admin',   '203.0.113.42', 'curl/7.68.0',          'failed'),
('2026-04-26 02:11:15', NULL,  'login_attempt', 'admin',   '203.0.113.42', 'curl/7.68.0',          'failed'),
('2026-04-26 02:11:16', NULL,  'login_attempt', 'admin',   '203.0.113.42', 'curl/7.68.0',          'failed'),
('2026-04-26 02:11:21', 1,     'login_success', 'admin',   '203.0.113.42', 'curl/7.68.0',          'suspicious'),
('2026-04-26 02:14:01', NULL,  'web_request',   '/upload/img_resize.php?cmd=id', '203.0.113.42', 'curl/7.68.0', 'suspicious'),
('2026-04-26 02:14:23', NULL,  'web_request',   '/upload/img_resize.php?cmd=cat /etc/passwd', '203.0.113.42', 'curl/7.68.0', 'suspicious'),
('2026-04-26 02:14:31', NULL,  'web_request',   '/images/cache/.thumbnails/proc.php', '203.0.113.42', 'python-requests/2.28.0', 'suspicious'),
('2026-04-26 02:14:55', 5,     'order_create',  'order#4', '203.0.113.42', 'python-requests/2.28.0', 'suspicious'),
('2026-04-26 02:31:14', 1,     'data_export',   'shopdb.users', '203.0.113.42', 'mysqldump', 'suspicious');

-- Session des Angreifers (noch aktiv)
INSERT INTO sessions (id, user_id, ip_address, user_agent, payload, expires_at) VALUES
('sess_ATTACKER_DEMO_FORENSIC_0001', 1, '203.0.113.42', 'python-requests/2.28.0',
 '{"user_id":1,"role":"admin","csrf":"DEMO_TOKEN"}',
 '2026-04-27 02:11:21');
