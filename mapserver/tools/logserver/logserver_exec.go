package main

import (
	"flag"

	"github.com/netsec-ethz/fpki/pkg/policylog/server/logserver"
)

func main() {
	flag.Parse()
	logserver.CreateLogServer("./tools/config/logserver_config.json")
}
