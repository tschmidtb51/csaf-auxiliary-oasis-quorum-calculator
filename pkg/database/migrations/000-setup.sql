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
    nickname  VARCHAR PRIMARY KEY,
    password  VARCHAR NOT NULL,
    firstname VARCHAR,
    lastname  VARCHAR,
    is_admin  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE sessions (
    token       VARCHAR   PRIMARY KEY,
    nickname    VARCHAR   NOT NULL REFERENCES users(nickname) ON DELETE CASCADE,
    last_access timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE committees (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        VARCHAR NOT NULL,
    description VARCHAR
);

CREATE TABLE committee_role (
    id          INTEGER PRIMARY KEY,
    name        VARCHAR NOT NULL,
    description VARCHAR NOT NULL,
    UNIQUE(name)
);

INSERT INTO committee_role (id, name, description) VALUES
    (0, 'member', 'Regular committee member'),
    (1, 'manager', 'Committee manager');

CREATE TABLE committee_roles (
    nickname          VARCHAR NOT NULL REFERENCES users(nickname)    ON DELETE CASCADE,
    committee_role_id INTEGER NOT NULL REFERENCES committee_role(id) ON DELETE CASCADE,
    committees_id     INTEGER NOT NULL REFERENCES committees(id)     ON DELETE CASCADE,
    UNIQUE(nickname, committee_role_id, committees_id)
);

CREATE TABLE meetings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    committees_id INTEGER   NOT NULL REFERENCES committees(id) ON DELETE CASCADE,
    running       BOOLEAN   NOT NULL DEFAULT FALSE,
    start_time    TIMESTAMP NOT NULL,
    stop_time     TIMESTAMP NOT NULL,
    description   VARCHAR,
    UNIQUE(committees_id, start_time),
    CHECK (strftime('%s', start_time) <= strftime('%s', stop_time))
);

CREATE TABLE attendees (
    meetings_id INTEGER NOT NULL REFERENCES meetings(id)    ON DELETE CASCADE,
    nickname    VARCHAR NOT NULL REFERENCES users(nickname) ON DELETE CASCADE,
    UNIQUE(meetings_id, nickname)
);

INSERT INTO users (nickname, password, lastname, is_admin)
    VALUES ('admin', {{ generatePassword "admin" | sqlQuote }}, 'Administrator', true);
