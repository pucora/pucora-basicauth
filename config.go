package basicauth

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"

	"github.com/pucora/lura/v2/config"
	"golang.org/x/crypto/bcrypt"
)

// Namespace is the key to use to store and access the custom config data.
const Namespace = "github.com/pucora/pucora-basicauth"

// Config holds basic authentication settings.
type Config struct {
	HtpasswdPath string            `json:"htpasswd_path"`
	Users        map[string]string `json:"users"`
}

// Credentials is a username to bcrypt hash map loaded at startup.
type Credentials map[string]string

// ParseConfig reads auth/basic settings from extra config.
func ParseConfig(e config.ExtraConfig) (Config, bool) {
	v, ok := e[Namespace]
	if !ok {
		return Config{}, false
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return Config{}, false
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, false
	}
	return cfg, true
}

// MergeConfig merges service-level defaults with endpoint-level overrides.
func MergeConfig(serviceCfg Config, endpoint config.ExtraConfig) (Config, bool) {
	_, epOK := endpoint[Namespace]
	if !epOK {
		return Config{}, false
	}
	epParsed, _ := ParseConfig(endpoint)
	if epParsed.HtpasswdPath == "" && len(epParsed.Users) == 0 {
		return serviceCfg, true
	}
	return epParsed, true
}

// LoadCredentials loads bcrypt credentials from config.
func LoadCredentials(cfg Config) (Credentials, error) {
	creds := Credentials{}
	if cfg.HtpasswdPath != "" {
		f, err := os.Open(cfg.HtpasswdPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			creds[parts[0]] = parts[1]
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	for user, hash := range cfg.Users {
		creds[user] = hash
	}
	return creds, nil
}

// Validate checks username and password against bcrypt hashes.
func (c Credentials) Validate(user, password string) bool {
	hash, ok := c[user]
	if !ok {
		return false
	}
	if strings.HasPrefix(hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
	}
	return hash == password
}
