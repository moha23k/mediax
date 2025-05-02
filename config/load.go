package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type ServerConfig struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	UseHTTPS bool   `json:"use_https"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PaginationConfig struct {
	PageSize int `json:"page_size"`
}

type AppConfig struct {
	Server            ServerConfig `json:"server"`
	User              User         `json:"user"`
	SessionTimeoutStr string       `json:"session_timeout"`
	SessionTimeout    time.Duration
	Pagination        PaginationConfig `json:"pagination"`
	Categories        []string         `json:"categories"`
	ApiKey            string           `json:"api_key"`
}

var App AppConfig

func LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("invalid config format: %w", err)
	}

	if cfg.Server.Address == "" {
		cfg.Server.Address = DefaultConfig.Server.Address
	} else if net.ParseIP(cfg.Server.Address) == nil {
		return fmt.Errorf("invalid server address: %s", cfg.Server.Address)
	}

	if cfg.Server.Port == 0 {
		cfg.Server.Port = DefaultConfig.Server.Port
	} else if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d (must be between 1 and 65535).", cfg.Server.Port)
	}

	if cfg.User.Username == "" {
		return errors.New("invalid user configuration: username must be set.")
	} else {
		usernameLength := len(cfg.User.Username)
		if usernameLength < 1 || usernameLength > 64 {
			return errors.New("invalid user configuration: username length must be between 1 and 64 characters.")
		}
	}

	if cfg.User.Password == "" {
		return errors.New("invalid user configuration: password must be set (should be bcrypt hashed).")
	}

	parsedTimeout, err := time.ParseDuration(cfg.SessionTimeoutStr)
	if err != nil {
		fmt.Printf("Warning: Invalid session_timeout: %s: %v. Using default.\n", cfg.SessionTimeoutStr, err)
		cfg.SessionTimeout = DefaultConfig.SessionTimeout
	} else {
		cfg.SessionTimeout = parsedTimeout
		if cfg.SessionTimeout <= 0 {
			fmt.Printf("Warning: Invalid session_timeout: %s. Using default.\n", cfg.SessionTimeoutStr)
			cfg.SessionTimeout = DefaultConfig.SessionTimeout
		}
	}

	if cfg.Pagination.PageSize < 10 || cfg.Pagination.PageSize > 50 {
		fmt.Printf("Warning: Invalid pagination page_size: %d (must be between 10 and 50). Using default.\n", cfg.Pagination.PageSize)
		cfg.Pagination.PageSize = DefaultConfig.Pagination.PageSize
	}

	if len(cfg.Categories) == 0 {
		cfg.Categories = DefaultConfig.Categories
	} else {
		for _, cat := range cfg.Categories {
			if !isValidCategory(cat) {
				return fmt.Errorf("Error: Invalid category: %s (allowed: %v)", cat, defaultCategories)
			}
		}
	}

	App = cfg
	return nil
}

func (u *User) CheckPassword(inputPassword string) bool {
	if strings.HasPrefix(u.Password, "{bcrypt}") {
		savedPassword := strings.TrimPrefix(u.Password, "{bcrypt}")
		return bcrypt.CompareHashAndPassword([]byte(savedPassword), []byte(inputPassword)) == nil
	}
	return false
}

func isValidCategory(cat string) bool {
	for _, valid := range defaultCategories {
		if cat == valid {
			return true
		}
	}
	return false
}
