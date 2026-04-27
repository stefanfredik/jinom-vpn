package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/jinom/vpn/pkg/mikrotik"
)

func main() {
	client, err := mikrotik.NewClient("10.70.94.190", "admin", "RexusBattlefire", true)
	if err != nil {
		log.Fatalf("Failed to connect to MikroTik: %v", err)
	}
	defer client.Close()

	fmt.Println("=== L2TP Client Config ===")
	l2tpIfaces, _ := client.Run("/interface/l2tp-client/print", nil)
	for _, iface := range l2tpIfaces {
		fmt.Printf("  name=%s connect-to=%s running=%s disabled=%s\n",
			iface["name"], iface["connect-to"], iface["running"], iface["disabled"])
		fmt.Printf("  use-ipsec=%s ipsec-secret=%s\n", iface["use-ipsec"], iface["ipsec-secret"])
		fmt.Printf("  user=%s allow=%s\n", iface["user"], iface["allow"])
	}

	fmt.Println("\n=== IPSec Profile ===")
	profiles, _ := client.Run("/ip/ipsec/profile/print", nil)
	for _, p := range profiles {
		fmt.Printf("  name=%s enc-algorithm=%s hash-algorithm=%s dh-group=%s\n",
			p["name"], p["enc-algorithm"], p["hash-algorithm"], p["dh-group"])
	}

	fmt.Println("\n=== IPSec Proposal ===")
	proposals, _ := client.Run("/ip/ipsec/proposal/print", nil)
	for _, p := range proposals {
		fmt.Printf("  name=%s enc-algorithms=%s auth-algorithms=%s pfs-group=%s\n",
			p["name"], p["enc-algorithms"], p["auth-algorithms"], p["pfs-group"])
	}

	fmt.Println("\n=== IPSec Peer ===")
	peers, _ := client.Run("/ip/ipsec/peer/print", nil)
	for _, p := range peers {
		fmt.Printf("  name=%s address=%s local-address=%s exchange-mode=%s profile=%s\n",
			p["name"], p["address"], p["local-address"], p["exchange-mode"], p["profile"])
	}

	fmt.Println("\n=== IPSec Identity ===")
	identities, _ := client.Run("/ip/ipsec/identity/print", nil)
	for _, id := range identities {
		for k, v := range id {
			fmt.Printf("  %s=%s\n", k, v)
		}
		fmt.Println("  ---")
	}

	fmt.Println("\n=== IPSec Active Peers ===")
	activePeers, _ := client.Run("/ip/ipsec/active-peers/print", nil)
	if len(activePeers) == 0 {
		fmt.Println("  (none)")
	}
	for _, p := range activePeers {
		fmt.Printf("  state=%s side=%s local=%s remote=%s\n",
			p["state"], p["side"], p["local-address"], p["remote-address"])
	}

	fmt.Println("\n=== Recent L2TP/IPSec Logs (last 40) ===")
	logs, _ := client.Run("/log/print", nil)
	count := 0
	for i := len(logs) - 1; i >= 0 && count < 40; i-- {
		msg := logs[i]["message"]
		topics := logs[i]["topics"]
		lower := strings.ToLower(msg) + strings.ToLower(topics)
		if strings.Contains(lower, "l2tp") || strings.Contains(lower, "ipsec") {
			fmt.Printf("  [%s] %s: %s\n", logs[i]["time"], topics, msg)
			count++
		}
	}
}
