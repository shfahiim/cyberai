package llm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type GlobalConfig struct {
	APIKeys map[string]string `json:"api_keys"`
	Models  map[string]string `json:"models"`
}

func GetGlobalConfigPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	if home == "" {
		return "", fmt.Errorf("cannot resolve home directory")
	}
	return filepath.Join(home, ".cyberai", "config.json"), nil
}

func LoadGlobalConfig() (*GlobalConfig, error) {
	path, err := GetGlobalConfigPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &GlobalConfig{
				APIKeys: make(map[string]string),
				Models:  make(map[string]string),
			}, nil
		}
		return nil, err
	}
	var cfg GlobalConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.APIKeys == nil {
		cfg.APIKeys = make(map[string]string)
	}
	if cfg.Models == nil {
		cfg.Models = make(map[string]string)
	}
	return &cfg, nil
}

func SaveGlobalConfig(cfg *GlobalConfig) error {
	path, err := GetGlobalConfigPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
