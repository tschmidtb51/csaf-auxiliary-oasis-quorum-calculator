-- This file is Free Software under the Apache-2.0 License
-- without warranty, see README.md and LICENSE for details.
--
-- SPDX-License-Identifier: Apache-2.0
--
-- SPDX-FileCopyrightText: 2025 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
-- Software-Engineering: 2025 Intevation GmbH <https://intevation.de>

CREATE TABLE versions (
    version     int       PRIMARY KEY,
    description text      NOT NULL,
    time        timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE users (
    nickname  varchar PRIMARY KEY,
    password  text NOT NULL,
    firstname varchar,
    lastname  varchar,
    is_admin  boolean DEFAULT false
);

CREATE TABLE sessions (
    nickname    varchar   NOT NULL REFERENCES users(nickname) ON DELETE CASCADE,
    last_access timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
    token       text      NOT NULL UNIQUE
);

INSERT INTO users (nickname, password, lastname, is_admin)
    VALUES ('admin', {{ generatePassword "admin" | sqlQuote }}, 'Administrator', true);
