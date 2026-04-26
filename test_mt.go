package main

import (
	"fmt"
	"log"

	"github.com/jinom/vpn/pkg/mikrotik"
)

func main() {
	client, err := mikrotik.NewClient("10.70.94.190", "admin", "admin123", true) 
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer client.Close()

    err = client.RunCommand(mikrotik.Command{
        Path: "/ip/route/add",
        Params: map[string]string{
            "dst-address": "10.250.0.0/16",
            "gateway":     "l2tp-jinom",
            "comment":     "jinom-nms",
        },
    })
    fmt.Printf("Error: %v\n", err)
}