-- SQLite schema per utenti e autenticazione
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    confirmed INTEGER DEFAULT 0,
    confirm_token TEXT
);

-- Puoi aggiungere altre tabelle (es. profili, log, ecc.)
