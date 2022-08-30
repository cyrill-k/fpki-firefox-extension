package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// global var for now
var mapResponder *responder.MapResponder

// ugly version.... I will refactor it later.

func main() {
	truncateTable()
	mapResponder = prepareMapServer()

	http.HandleFunc("/", helloWorld)
	http.ListenAndServe(":8080", nil)
}

func helloWorld(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case "GET":
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		queriedDomain := r.URL.Query()["domain"][0]

		response, err := mapResponder.GetProof(ctx, queriedDomain)
		if err != nil {
			log.Fatal(err)
			return
		}

		bytes, err := serialiseMapResp(response)
		if err != nil {
			log.Fatal(err)
			return
		}
		w.Write(bytes)
	default:
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
	}
}

func serialiseMapResp(response []mapCommon.MapServerResponse) ([]byte, error) {
	bytes, err := json.MarshalIndent(response, "", " ")
	if err != nil {
		return nil, fmt.Errorf("serialiseMapResp | MarshalIndent | %w", err)
	}
	return bytes, nil
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

	err = db.Close()
	if err != nil {
		panic(err)
	}
}

func prepareMapServer() *responder.MapResponder {
	mapUpdater, err := updater.NewMapUpdater(nil, 233)
	if err != nil {
		panic(err)
	}

	rpcs, sps, err := getRPCAndSP()
	if err != nil {
		panic(err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	err = mapUpdater.UpdateRPCAndPCLocally(ctx, sps, rpcs)
	if err != nil {
		panic(err)
	}

	err = mapUpdater.CommitSMTChanges(ctx)
	if err != nil {
		panic(err)
	}

	root := mapUpdater.GetRoot()
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	// get a new responder, and load an existing tree
	mapResponder, err := responder.NewMapResponder(ctx, root, 233, "./config/mapserver_config.json")
	if err != nil {
		panic(err)
	}

	return mapResponder
}

func getRPCAndSP() ([]*common.RPC, []*common.SP, error) {
	rpcs := []*common.RPC{}
	sps := []*common.SP{}

	fileInfos, err := ioutil.ReadDir("./rpc_and_sp")
	if err != nil {
		return nil, nil, fmt.Errorf("getRPCAndSP | ReadDir | %w", err)
	}

	for _, f := range fileInfos {
		switch f.Name()[len(f.Name())-3:] {
		case "_sp":
			sp := &common.SP{}
			err = common.JsonFileToSP(sp, "./rpc_and_sp/"+f.Name())
			if err != nil {
				return nil, nil, fmt.Errorf("getRPCAndSP | JsonFileToSP | %w", err)
			}
			sps = append(sps, sp)
		case "rpc":
			rpc := &common.RPC{}
			err = common.JsonFileToRPC(rpc, "./rpc_and_sp/"+f.Name())
			if err != nil {
				return nil, nil, fmt.Errorf("getRPCAndSP | JsonFileToRPC | %w", err)
			}
			rpcs = append(rpcs, rpc)
		default:
			continue
		}
	}
	return rpcs, sps, nil
}
