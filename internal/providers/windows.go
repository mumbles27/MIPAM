package providers

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf16"
)

//go:embed windows.ps1
var windowsScript string

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("PowerShell output limit exceeded")
	}
	return b.Buffer.Write(p)
}

// WindowsExecute uses the service identity and a locally configured server only.
// User input is JSON on stdin, never executable PowerShell source.
func WindowsExecute(ctx context.Context, server string, r Request) (json.RawMessage, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("Windows DNS/DHCP management requires the Windows connector")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	mask := ""
	if r.CIDR != "" {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return nil, err
		}
		mask = net.IP(net.CIDRMask(p.Bits(), 32)).String()
	}
	if r.Kind == "dns" && r.Name != "" {
		full := recordName(r)
		zone := fqdn(r.Zone)
		if full == zone {
			r.Name = "@"
		} else {
			r.Name = strings.TrimSuffix(full, "."+zone)
		}
		r.Zone = strings.TrimSuffix(r.Zone, ".")
	}
	input, err := json.Marshal(map[string]any{"server": server, "mask": mask, "request": r})
	if err != nil {
		return nil, err
	}
	u16 := utf16.Encode([]rune(windowsScript))
	encoded := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(encoded[i*2:], v)
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
	cmd.Stdin = bytes.NewReader(input)
	stdout, stderr := &cappedBuffer{limit: 8 << 20}, &cappedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err = cmd.Run(); err != nil {
		return nil, errors.New("Windows operation failed; check connector service identity, modules, permissions, and server logs; reconcile before retrying writes")
	}
	out := bytes.TrimSpace(stdout.Bytes())
	out = bytes.TrimPrefix(out, []byte{0xef, 0xbb, 0xbf})
	if !json.Valid(out) {
		return nil, errors.New("Windows operation returned invalid JSON")
	}
	return json.RawMessage(out), nil
}
