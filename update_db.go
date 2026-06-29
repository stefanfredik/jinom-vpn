package main

import (
	"database/sql"
	"fmt"
	"log"
	_ "github.com/lib/pq"
)

func main() {
	connStr := "host=127.0.0.1 port=5432 user=jinom password=j1n0m dbname=nms_db sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil { log.Fatal(err) }
	
	rows, err := db.Query("SELECT column_name FROM information_schema.columns WHERE table_name='reseller_tunnels'")
	if err != nil { log.Fatal(err) }
	
	for rows.Next() {
		var name string
		rows.Scan(&name)
		fmt.Println(name)
	}
}
