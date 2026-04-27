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

	fmt.Println("=== L2TP Client Interfaces ===")
	l2tpIfaces, err := client.Run("/interface/l2tp-client/print", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	for _, iface := range l2tpIfaces {
		for k, v := range iface {
			fmt.Printf("  %s = %s\n", k, v)
		}
		fmt.Println("  ---")
	}

	fmt.Println("\n=== IPSec Policies ===")
	policies, err := client.Run("/ip/ipsec/policy/print", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	for _, p := range policies {
		for k, v := range p {
			fmt.Printf("  %s = %s\n", k, v)
		}
		fmt.Println("  ---")
	}

	fmt.Println("\n=== IPSec Peers ===")
	peers, err := client.Run("/ip/ipsec/peer/print", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	for _, p := range peers {
		for k, v := range p {
			fmt.Printf("  %s = %s\n", k, v)
		}
		fmt.Println("  ---")
	}

	fmt.Println("\n=== IPSec Active Peers (SAs) ===")
	activePeers, err := client.Run("/ip/ipsec/active-peers/print", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	if len(activePeers) == 0 {
		fmt.Println("  (no active peers)")
	}
	for _, p := range activePeers {
		for k, v := range p {
			fmt.Printf("  %s = %s\n", k, v)
		}
		fmt.Println("  ---")
	}

	fmt.Println("\n=== IPSec Installed SAs ===")
	installedSA, err := client.Run("/ip/ipsec/installed-sa/print", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	if len(installedSA) == 0 {
		fmt.Println("  (no installed SAs)")
	}
	for _, sa := range installedSA {
		for k, v := range sa {
			fmt.Printf("  %s = %s\n", k, v)
		}
		fmt.Println("  ---")
	}

	fmt.Println("\n=== Recent Logs (L2TP/IPSec related) ===")
	logs, err := client.Run("/log/print", nil)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	count := 0
	for i := len(logs) - 1; i >= 0 && count < 30; i-- {
		msg := logs[i]["message"]
		topics := logs[i]["topics"]
		if strings.Contains(strings.ToLower(msg), "l2tp") ||
			strings.Contains(strings.ToLower(msg), "ipsec") ||
			strings.Contains(strings.ToLower(topics), "l2tp") ||
			strings.Contains(strings.ToLower(topics), "ipsec") {
			fmt.Printf("  [%s] %s: %s\n", logs[i]["time"], topics, msg)
			count++
		}
	}
	if count == 0 {
		fmt.Println("  (no L2TP/IPSec logs found)")
	}
}
