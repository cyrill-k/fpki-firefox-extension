package main

import (
	"flag"

	"github.com/netsec-ethz/fpki/pkg/policylog/server/logsigner"
)

func main() {
	flag.Parse()
	logsigner.CreateLogSigner("./tools/config/logsigner_config.json")
}
