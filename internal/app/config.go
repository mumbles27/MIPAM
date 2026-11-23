package app

import (
	"encoding/json"
	"errors"
	"os"
	"time"
)

type Config struct {
	Listen         string           `json:"listen"`
	Database       string           `json:"database"`
	PublicURL      string           `json:"public_url"`
	TLSCert        string           `json:"tls_cert"`
	TLSKey         string           `json:"tls_key"`
	LogFile        string           `json:"log_file"`
	BackupDir      string           `json:"backup_dir"`
	BackupKeyFile  string           `json:"backup_key_file"`
	BackupHours    int              `json:"backup_hours"`
	BackupKeep     int              `json:"backup_keep"`
	SessionHours   int              `json:"session_hours"`
	SIEMURL        string           `json:"siem_url"`
	SIEMTokenEnv   string           `json:"siem_token_env"`
	SIEMQueueLimit int              `json:"siem_queue_limit"`
	OIDC           OIDCConfig       `json:"oidc"`
	LDAP           LDAPConfig       `json:"ldap"`
	SAML           SAMLConfig       `json:"saml"`
	Providers      []ProviderConfig `json:"providers"`
	SNMP           []SNMPConfig     `json:"snmp"`
}

type SNMPConfig struct {
	ID         string `json:"id"`
	Host       string `json:"host"`
	User       string `json:"user"`
	AuthEnv    string `json:"auth_env"`
	PrivacyEnv string `json:"privacy_env"`
}

type SAMLConfig struct {
	MetadataFile    string              `json:"metadata_file"`
	CertificateFile string              `json:"certificate_file"`
	KeyFile         string              `json:"key_file"`
	GroupAttribute  string              `json:"group_attribute"`
	GroupRoles      map[string]string   `json:"group_roles"`
	GroupSites      map[string][]string `json:"group_sites"`
}

type ProviderConfig struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	URL         string `json:"url"`
	Server      string `json:"server"`
	SecretEnv   string `json:"secret_env"`
	AllowWrites bool   `json:"allow_writes"`
	CAFile      string `json:"ca_file"`
	CertFile    string `json:"cert_file"`
	KeyFile     string `json:"key_file"`
}

type OIDCConfig struct {
	Issuer     string              `json:"issuer"`
	ClientID   string              `json:"client_id"`
	SecretEnv  string              `json:"secret_env"`
	GroupClaim string              `json:"group_claim"`
	GroupRoles map[string]string   `json:"group_roles"`
	GroupSites map[string][]string `json:"group_sites"`
}

type LDAPConfig struct {
	URL         string              `json:"url"`
	BaseDN      string              `json:"base_dn"`
	BindDN      string              `json:"bind_dn"`
	PasswordEnv string              `json:"password_env"`
	GroupRoles  map[string]string   `json:"group_roles"`
	GroupSites  map[string][]string `json:"group_sites"`
}

func LoadConfig(path string) (Config, error) {
	c := Config{
		Listen: "127.0.0.1:8080", Database: "data/mipam.db",
		PublicURL: "http://127.0.0.1:8080", BackupDir: "data/backups",
		BackupKeyFile: "data/backup.key", BackupKeep: 14, SessionHours: 8,
		SIEMQueueLimit: 100000,
	}
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return c, err
		}
		defer f.Close()
		d := json.NewDecoder(f)
		d.DisallowUnknownFields()
		if err := d.Decode(&c); err != nil {
			return c, err
		}
	}
	if c.SessionHours < 1 || c.SessionHours > 168 {
		return c, errors.New("session_hours must be 1..168")
	}
	if c.BackupHours < 0 || c.BackupKeep < 1 {
		return c, errors.New("invalid backup schedule or retention")
	}
	if c.SIEMQueueLimit < 1 {
		return c, errors.New("siem_queue_limit must be positive")
	}
	return c, nil
}

func (c Config) sessionDuration() time.Duration { return time.Duration(c.SessionHours) * time.Hour }
