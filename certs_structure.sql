CREATE TABLE IF NOT EXISTS certs (
    serial TEXT NOT NULL,
    domain TEXT NOT NULL,
    name TEXT NOT NULL,
    notbefore INTEGER NOT NULL,
    notafter INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lastupdates (
    domain TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL
);
