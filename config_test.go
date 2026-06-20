package basicauth_test

import (
	"testing"

	basicauth "github.com/pucora/pucora-basicauth/v2"
	"golang.org/x/crypto/bcrypt"
)

func TestValidateBcrypt(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	creds := basicauth.Credentials{"alice": string(hash)}
	if !creds.Validate("alice", "secret") {
		t.Fatal("expected valid credentials")
	}
	if creds.Validate("alice", "wrong") {
		t.Fatal("expected invalid credentials")
	}
}

func TestMergeConfigInheritsService(t *testing.T) {
	ep := map[string]interface{}{
		"github.com/pucora/pucora-basicauth": map[string]interface{}{},
	}
	cfg, ok := basicauth.MergeConfig(basicauth.Config{HtpasswdPath: "/tmp/.htpasswd"}, ep)
	if !ok || cfg.HtpasswdPath != "/tmp/.htpasswd" {
		t.Fatalf("expected inherited config, got %+v ok=%v", cfg, ok)
	}
}
