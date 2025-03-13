// This file is Free Software under the Apache-2.0 License
// without warranty, see README.md and LICENSE for details.
//
// SPDX-License-Identifier: Apache-2.0
//
// SPDX-FileCopyrightText: 2024 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
// Software-Engineering: 2024 Intevation GmbH <https://intevation.de>

// Package config implements the configuration mechanisms.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/BurntSushi/toml"
)

// DefaultConfigFile is the name of the default config file.
const DefaultConfigFile = "oqcd.toml"

const (
	defaultLogFile   = "isduba.log"
	defaultLogLevel  = slog.LevelInfo
	defaultLogSource = false
	defaultLogJSON   = false
)

const (
	defaultWebHost   = "localhost"
	defaultWebPort   = 8083
	defaultWebStatic = "web"
)

const (
	defaultDatabaseURL                     = "oqcd.sqlite"
	defaultDatabaseDriver                  = "sqlite3"
	defaultDatabaseMigrate                 = false
	defaultDatabaseTerminateAfterMigration = true
)

// Log are the config options for the logging.
type Log struct {
	File   string     `toml:"file"`
	Level  slog.Level `toml:"level"`
	Source bool       `toml:"source"`
	JSON   bool       `toml:"json"`
}

// Web are the config options for the web interface.
type Web struct {
	Host   string `toml:"host"`
	Port   int    `toml:"port"`
	Static string `toml:"static"`
}

// Database are the config options for the database.
type Database struct {
	DatabaseURL             string `toml:"database"`
	Migrate                 bool   `toml:"migrate"`
	TerminateAfterMigration bool   `toml:"terminate_after_migration"`
}

// Config are all the configuration options.
type Config struct {
	Log      Log      `toml:"log"`
	Web      Web      `toml:"web"`
	Database Database `toml:"database"`
}

// Addr returns the combined address the web server should bind to.
func (w *Web) Addr() string {
	return net.JoinHostPort(w.Host, strconv.Itoa(w.Port))
}

// Load loads the configuration from a given file. An empty string
// resorts to the default configuration.
func Load(file string) (*Config, error) {
	cfg := &Config{
		Log: Log{
			File:   defaultLogFile,
			Level:  defaultLogLevel,
			Source: defaultLogSource,
			JSON:   defaultLogJSON,
		},
		Web: Web{
			Host:   defaultWebHost,
			Port:   defaultWebPort,
			Static: defaultWebStatic,
		},
		Database: Database{
			DatabaseURL:             defaultDatabaseURL,
			Migrate:                 defaultDatabaseMigrate,
			TerminateAfterMigration: defaultDatabaseTerminateAfterMigration,
		},
	}
	if file != "" {
		md, err := toml.DecodeFile(file, cfg)
		if err != nil {
			return nil, err
		}
		// Don't accept unknown entries in config file.
		if undecoded := md.Undecoded(); len(undecoded) != 0 {
			return nil, fmt.Errorf("config: could not parse %q", undecoded)
		}
	}
	if err := cfg.fillFromEnv(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) fillFromEnv() error {
	var (
		storeString = store(noparse)
		storeInt    = store(strconv.Atoi)
		storeBool   = store(strconv.ParseBool)
		storeLevel  = store(storeLevel)
	)
	return storeFromEnv(
		envStore{"ISDUBA_LOG_FILE", storeString(&cfg.Log.File)},
		envStore{"ISDUBA_LOG_LEVEL", storeLevel(&cfg.Log.Level)},
		envStore{"ISDUBA_LOG_JSON", storeBool(&cfg.Log.JSON)},
		envStore{"ISDUBA_LOG_SOURCE", storeBool(&cfg.Log.Source)},
		envStore{"ISDUBA_WEB_HOST", storeString(&cfg.Web.Host)},
		envStore{"ISDUBA_WEB_PORT", storeInt(&cfg.Web.Port)},
		envStore{"ISDUBA_WEB_STATIC", storeString(&cfg.Web.Static)},
		envStore{"ISDUBA_DB_URL", storeString(&cfg.Database.DatabaseURL)},
		envStore{"ISDUBA_DB_MIGRATE", storeBool(&cfg.Database.Migrate)},
		envStore{"ISDUBA_DB_TERMINATE_AFTER_MIGRATION", storeBool(&cfg.Database.TerminateAfterMigration)},
	)
}
