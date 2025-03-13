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
