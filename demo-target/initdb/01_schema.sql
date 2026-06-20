-- ─────────────────────────────────────────────────────────────────────────
-- FORENSIC DEMO DATABASE — shopdb
-- Enthält typische forensisch relevante Daten:
--   • Benutzer-Tabelle mit Passwort-Hashes
--   • Audit-Log mit Aktivitäten
--   • Zahlungsdaten (anonymisiert / Demo)
-- ─────────────────────────────────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS shopdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE shopdb;

-- Benutzer-Tabelle
CREATE TABLE users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50) UNIQUE NOT NULL,
    email         VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('customer','admin','moderator') DEFAULT 'customer',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME,
    ip_address    VARCHAR(45),
    is_active     TINYINT(1) DEFAULT 1
);

-- Bestellungen
CREATE TABLE orders (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,
    total       DECIMAL(10,2),
    status      ENUM('pending','paid','shipped','cancelled') DEFAULT 'pending',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Zahlungsmethoden (FORENSIK-ARTEFAKT: CC-Daten in DB)
CREATE TABLE payment_methods (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    user_id      INT,
    card_number  VARCHAR(20),
    card_holder  VARCHAR(100),
    expiry       VARCHAR(7),
    cvv          VARCHAR(4),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Audit-Log (forensisch wertvoll)
CREATE TABLE audit_log (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_id     INT,
    action      VARCHAR(100),
    target      VARCHAR(200),
    ip_address  VARCHAR(45),
    user_agent  TEXT,
    status      ENUM('success','failed','suspicious') DEFAULT 'success'
);

-- Session-Tabelle
CREATE TABLE sessions (
    id         VARCHAR(128) PRIMARY KEY,
    user_id    INT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    payload    TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
);
