package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
)

type keaReply struct {
	Result    int             `json:"result"`
	Text      string          `json:"text"`
	Arguments json.RawMessage `json:"arguments"`
}

func keaCommand(ctx context.Context, c Config, command string, args any) (json.RawMessage, error) {
	body := map[string]any{"command": command}
	if args != nil {
		body["arguments"] = args
	}
	raw, err := request(ctx, c, "POST", "", body)
	if err != nil {
		return nil, err
	}
	var result keaReply
	if len(raw) > 0 && raw[0] == '[' {
		var results []keaReply
		if err = json.Unmarshal(raw, &results); err != nil || len(results) != 1 {
			return nil, errors.New("unexpected Kea response")
		}
		result = results[0]
	} else {
		if err = json.Unmarshal(raw, &result); err != nil {
			return nil, err
		}
	}
	if result.Result != 0 && result.Result != 3 {
		return nil, fmt.Errorf("Kea command %s failed (code %d)", command, result.Result)
	}
	if len(result.Arguments) == 0 {
		return json.RawMessage(`null`), nil
	}
	return result.Arguments, nil
}
func keaCapabilities(ctx context.Context, c Config, command string) error {
	raw, err := keaCommand(ctx, c, "list-commands", nil)
	if err != nil {
		return err
	}
	var commands []string
	if err = json.Unmarshal(raw, &commands); err != nil {
		return err
	}
	if !slices.Contains(commands, command) {
		return fmt.Errorf("Kea does not expose %s; required hook may be unavailable", command)
	}
	return nil
}
func keaRead(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	switch r.Kind {
	case "scope":
		raw, err := keaCommand(ctx, c, "config-get", nil)
		if err != nil {
			return nil, err
		}
		// config-get can contain database passwords and hook credentials. Return
		// only typed subnet/pool inventory, never persist the original response.
		type pool struct {
			Pool string `json:"pool"`
		}
		type subnet struct {
			ID    uint32 `json:"id"`
			CIDR  string `json:"subnet"`
			Pools []pool `json:"pools"`
		}
		var conf struct {
			DHCP4 struct {
				Subnets []subnet `json:"subnet4"`
				Shared  []struct {
					Subnets []subnet `json:"subnet4"`
				} `json:"shared-networks"`
			} `json:"Dhcp4"`
		}
		if err = json.Unmarshal(raw, &conf); err != nil {
			return nil, err
		}
		all := append([]subnet{}, conf.DHCP4.Subnets...)
		for _, shared := range conf.DHCP4.Shared {
			all = append(all, shared.Subnets...)
		}
		return json.Marshal(map[string]any{"Dhcp4": map[string]any{"subnet4": all}})
	case "reservation":
		if r.SubnetID == 0 {
			return nil, errors.New("Kea subnet_id required")
		}
		args := map[string]any{"subnet-id": r.SubnetID}
		cmd := "reservation-get-all"
		if r.IP != "" {
			cmd = "reservation-get"
			args["ip-address"] = r.IP
		}
		if err := keaCapabilities(ctx, c, cmd); err != nil {
			return nil, err
		}
		return keaCommand(ctx, c, cmd, args)
	case "lease":
		if r.SubnetID == 0 {
			return nil, errors.New("Kea subnet_id required")
		}
		if err := keaCapabilities(ctx, c, "lease4-get-page"); err != nil {
			return nil, err
		}
		// Bounded page; returned provider next marker can be inspected by the operator.
		from := r.IP
		if from == "" {
			from = "start"
		}
		raw, err := keaCommand(ctx, c, "lease4-get-page", map[string]any{"from": from, "limit": 1000})
		if err != nil {
			return nil, err
		}
		var page struct {
			Leases []json.RawMessage `json:"leases"`
			Next   string            `json:"next"`
		}
		if err = json.Unmarshal(raw, &page); err != nil {
			return nil, err
		}
		filtered := []json.RawMessage{}
		for _, raw := range page.Leases {
			var lease struct {
				Subnet uint32 `json:"subnet-id"`
			}
			if json.Unmarshal(raw, &lease) == nil && lease.Subnet == r.SubnetID {
				filtered = append(filtered, raw)
			}
		}
		return json.Marshal(map[string]any{"leases": filtered, "next": page.Next})
	default:
		return nil, errors.New("Kea supports DHCP scopes, reservations and leases")
	}
}
func keaApply(ctx context.Context, c Config, r Request) (json.RawMessage, error) {
	if r.Kind != "reservation" {
		return nil, errors.New("Kea scope mutation is not yet supported; use native Kea configuration management")
	}
	if r.SubnetID == 0 {
		return nil, errors.New("Kea subnet_id required")
	}
	cmd := map[string]string{"create": "reservation-add", "update": "reservation-update", "delete": "reservation-del"}[r.Action]
	if err := keaCapabilities(ctx, c, cmd); err != nil {
		return nil, err
	}
	var args any
	if r.Action == "delete" {
		args = map[string]any{"subnet-id": r.SubnetID, "ip-address": r.IP}
	} else {
		mac, _ := net.ParseMAC(r.MAC)
		args = map[string]any{"reservation": map[string]any{"subnet-id": r.SubnetID, "ip-address": r.IP, "hw-address": mac.String(), "hostname": r.Name}}
	}
	if _, err := keaCommand(ctx, c, cmd, args); err != nil {
		return nil, err
	}
	after, err := keaRead(ctx, c, r)
	if err != nil {
		return nil, errors.New("write submitted; read-back failed; reconcile before retry")
	}
	var obj struct {
		IP  string `json:"ip-address"`
		MAC string `json:"hw-address"`
	}
	if err = json.Unmarshal(after, &obj); err != nil {
		return nil, err
	}
	if r.Action == "delete" {
		if obj.IP != "" {
			return nil, errors.New("reservation still present after deletion")
		}
	} else {
		want, _ := net.ParseMAC(r.MAC)
		got, _ := net.ParseMAC(obj.MAC)
		if obj.IP != r.IP || got.String() != want.String() {
			return nil, errors.New("reservation read-back mismatch")
		}
	}
	return after, nil
}
