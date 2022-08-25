package main

import (
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

func main() {

}

func truncateTable() {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/fpki?maxAllowedPacket=1073741824")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE domainEntries;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE updates;")
	if err != nil {
		panic(err)
	}

	_, err = db.Exec("TRUNCATE tree;")
	if err != nil {
		panic(err)
	}
}
