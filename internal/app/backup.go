package app

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const backupMagic = "MIPAM-BACKUP-1\n"
const backupLimit = 256 << 20

type backupPayload struct {
	Schema   int    `json:"schema"`
	Created  string `json:"created"`
	SHA256   string `json:"sha256"`
	Database []byte `json:"database"`
	Config   Config `json:"config"`
}

func InitBackupKey(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	if _, err = f.Write(key); err != nil {
		return err
	}
	return f.Sync()
}
func backupCipher(keyFile string) (cipher.AEAD, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, errors.New("backup key unavailable; initialize and securely escrow it")
	}
	if len(key) != 32 {
		return nil, errors.New("backup key must contain exactly 32 raw bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func (a *Server) Backup(ctx context.Context) (string, error) {
	a.backupMu.Lock()
	defer a.backupMu.Unlock()
	gcm, err := backupCipher(a.C.BackupKeyFile)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(a.C.BackupDir, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(a.C.BackupDir, ".snapshot-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	path, err := filepath.Abs(filepath.Join(dir, "snapshot.db"))
	if err != nil {
		return "", err
	}
	if _, err = a.S.DB.ExecContext(ctx, "VACUUM INTO ?", path); err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > 128<<20 {
		return "", errors.New("built-in encrypted backup limit is 128 MiB; use an offline database backup for larger deployments")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	payload, err := json.Marshal(backupPayload{Schema: 1, Created: now(), SHA256: hex.EncodeToString(sum[:]), Database: data, Config: a.C})
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return "", err
	}
	content := append([]byte(backupMagic), nonce...)
	content = gcm.Seal(content, nonce, payload, []byte(backupMagic))
	name := "mipam-" + time.Now().UTC().Format("20060102T150405") + "-" + newID()[:8] + ".mipambak"
	tmp := filepath.Join(dir, "encrypted")
	if err = os.WriteFile(tmp, content, 0600); err != nil {
		return "", err
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		return "", err
	}
	target := filepath.Join(a.C.BackupDir, name)
	if err = os.Rename(tmp, target); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(a.C.BackupDir)
	if err != nil {
		return target, err
	}
	names := []string{}
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "mipam-") && strings.HasSuffix(e.Name(), ".mipambak") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	for len(names) > a.C.BackupKeep {
		if err = os.Remove(filepath.Join(a.C.BackupDir, names[0])); err != nil {
			return target, err
		}
		names = names[1:]
	}
	return target, nil
}

// Restore always creates a new staging directory, never overwrites a live installation.
func Restore(backup, keyFile, destination string) error {
	gcm, err := backupCipher(keyFile)
	if err != nil {
		return err
	}
	f, err := os.Open(backup)
	if err != nil {
		return err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, backupLimit+1))
	if err != nil {
		return err
	}
	if len(raw) > backupLimit || len(raw) < len(backupMagic)+gcm.NonceSize() || string(raw[:len(backupMagic)]) != backupMagic {
		return errors.New("invalid or oversized backup")
	}
	raw = raw[len(backupMagic):]
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(backupMagic))
	if err != nil {
		return errors.New("backup authentication failed")
	}
	var payload backupPayload
	if err = json.Unmarshal(plain, &payload); err != nil {
		return err
	}
	sum := sha256.Sum256(payload.Database)
	if payload.Schema != 1 || payload.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("backup schema/checksum mismatch")
	}
	if _, err = os.Lstat(destination); !os.IsNotExist(err) {
		return errors.New("restore destination must not exist")
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		return err
	}
	path := filepath.Join(destination, "mipam.db")
	if err = os.WriteFile(path, payload.Database, 0600); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err = db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("restored database failed integrity check")
	}
	var version int
	if err = db.QueryRow("SELECT version FROM schema_version").Scan(&version); err != nil || version != 1 {
		return errors.New("unsupported restored schema")
	}
	_, err = db.Exec("DELETE FROM sessions; DELETE FROM auth_flows; UPDATE jobs SET status='interrupted',result='Restored backup: external reconciliation required' WHERE status IN ('running','queued','preview')")
	if err != nil {
		return err
	}
	if err = db.Close(); err != nil {
		return err
	}
	cfg, _ := json.MarshalIndent(payload.Config, "", "  ")
	return os.WriteFile(filepath.Join(destination, "config.reference.json"), cfg, 0600)
}
func (a *Server) createBackup(w http.ResponseWriter, r *http.Request) {
	if !a.admin(w, r) {
		return
	}
	if err := a.audit(r.Context(), principal(r).ID, "backup.start", "database", ""); err != nil {
		a.internal(w, err)
		return
	}
	path, err := a.Backup(r.Context())
	if err != nil {
		a.internal(w, err)
		return
	}
	if err = a.audit(r.Context(), principal(r).ID, "backup.complete", filepath.Base(path), ""); err != nil {
		a.internal(w, err)
		return
	}
	respond(w, 200, map[string]string{"file": filepath.Base(path), "message": "Encrypted backup stored on server; escrow the key separately. Restore is an offline staging command."})
}
