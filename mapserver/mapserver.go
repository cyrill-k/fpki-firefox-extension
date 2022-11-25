package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/netsec-ethz/fpki/pkg/common"
	mapCommon "github.com/netsec-ethz/fpki/pkg/mapserver/common"
	"github.com/netsec-ethz/fpki/pkg/mapserver/responder"
	"github.com/netsec-ethz/fpki/pkg/mapserver/updater"
)

// global var for now
var mapResponder *responder.MapResponder

var queryCounterChannel = make(chan int)

// ugly version.... I will refactor it later.
func main() {
	truncateTable()
	mapResponder = prepareMapServer()

	go func(counterChannel chan int) {
		counter := 0
		for {
			counterChannel <- counter
			counter += 1
		}
	}(queryCounterChannel)

	var s = http.Server{
		Addr:        ":8080",
		Handler:     http.HandlerFunc(mapServerQueryHandler),
		IdleTimeout: 5 * time.Second,
	}
	s.ListenAndServe()
}

func mapServerQueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case "GET":
		queryIndex := <-queryCounterChannel
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
		defer cancelF()

		queriedDomain := r.URL.Query()["domain"][0]
		fmt.Println("[", queryIndex, "] get domain request:", queriedDomain)

		fmt.Println("[", queryIndex, "] receive a request from:", r.RemoteAddr, r.Header)

		response, err := mapResponder.GetProof(ctx, queriedDomain)
		if err != nil {
			log.Fatal(err)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)

		fmt.Println("[", queryIndex, "] replying for domain request: ", queriedDomain)
		// inspectResponse(response)

	default:
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
	}
}

func inspectResponse(response []mapCommon.MapServerResponse) {
	//spew.Dump(response[0].DomainEntryBytes)
	key := common.SHA256Hash([]byte(response[0].Domain))
	value := common.SHA256Hash([]byte(response[0].DomainEntryBytes))

	//fmt.Println(value)
	//fmt.Println(key)
	//fmt.Println(SHA256Hash(key, value, []byte{byte(256 - len(response[0].PoI.Proof))}))
	hT := append(append(key, value...), []byte{byte(256 - len(response[0].PoI.Proof))}...)

	fmt.Println("first hash", common.SHA256Hash(hT))
	fmt.Println(VerifyInclusion(response[0].PoI.Root, response[0].PoI.Proof, common.SHA256Hash([]byte(response[0].Domain)),
		value))

	uEnc := base64.URLEncoding.EncodeToString(response[0].PoI.Root)
	fmt.Println(uEnc)

	//sss, _ := json.Marshal(response)
	//spew.Dump(sss)

	fmt.Println("root value", response[0].PoI.Root)

	sDec, err := base64.StdEncoding.DecodeString("u+ZkpW54sUIb+DvvB5JO9vprCQAo6fChy1j92YwZ0Lo=")
	if err != nil {
		panic(err)
	}
	fmt.Println(sDec)
	fmt.Println()
}

// VerifyInclusion verifies that key/value is included in the trie with latest root
func VerifyInclusion(root []byte, ap [][]byte, key, value []byte) bool {
	leafHash := common.SHA256Hash(key, value, []byte{byte(256 - len(ap))})
	return bytes.Equal(root, verifyInclusion(ap, 0, key, leafHash))
}

// verifyInclusion returns the merkle root by hashing the merkle proof items
func verifyInclusion(ap [][]byte, keyIndex int, key, leafHash []byte) []byte {
	if keyIndex == len(ap) {
		fmt.Println("hash at ", keyIndex, " ", leafHash)
		return leafHash
	}
	if bitIsSet(key, keyIndex) {
		neighbor := verifyInclusion(ap, keyIndex+1, key, leafHash)
		result := common.SHA256Hash(ap[len(ap)-keyIndex-1], neighbor)
		fmt.Println("hash at ", keyIndex, " ", result, " ", len(ap)-keyIndex-1)
		fmt.Println(ap[len(ap)-keyIndex-1])
		fmt.Println(neighbor)
		fmt.Println("*******************************")
		return result
	}

	neighbor := verifyInclusion(ap, keyIndex+1, key, leafHash)
	result := common.SHA256Hash(neighbor, ap[len(ap)-keyIndex-1])
	fmt.Println("hash at ", keyIndex, " ", result, " ", len(ap)-keyIndex-1)
	fmt.Println(neighbor)
	fmt.Println(ap[len(ap)-keyIndex-1])
	fmt.Println("*******************************")

	return result
}

func bitIsSet(bits []byte, i int) bool {
	return bits[i/8]&(1<<uint(7-i%8)) != 0
}

/*
   // Hash exports default hash function for trie
   var SHA256Hash = func(data ...[]byte) []byte {
	hash := sha256.New()

	for i := 0; i < len(data); i++ {
		hash.Write(data[i])
		fmt.Println(data[i])
		fmt.Println(len(data[i]))
	}

	//fmt.Println(hash.Size())
	return hash.Sum(nil)
    }*/

func truncateTable() {
	env := map[string]string{"MYSQL_USER": "root", "MYSQL_PASSWORD": "", "MYSQL_HOST": "localhost", "MYSQL_PORT": ""}
	for k := range env {
		v, exists := os.LookupEnv(k)
		if exists {
			env[k] = v
		}
	}
	dsnString := env["MYSQL_USER"]
	if env["MYSQL_PASSWORD"] != "" {
		dsnString += ":" + env["MYSQL_PASSWORD"]
	}
	dsnString += "@tcp(" + env["MYSQL_HOST"]
	if env["MYSQL_PORT"] != "" {
		dsnString += ":" + env["MYSQL_PORT"]
	}
	dsnString += ")/fpki?maxAllowedPacket=1073741824"
	fmt.Printf("mapserver | truncateTable | using dsn: %s\n", dsnString)
	db, err := sql.Open("mysql", dsnString)
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

	certs, err := getCerts()
	if err != nil {
		panic(err)
	}
	for _, v := range certs {
		fmt.Println(v.Subject)
	}

	ctx, cancelFCerts := context.WithTimeout(context.Background(), time.Second*10)
	defer cancelFCerts()
	err = mapUpdater.UpdateCertsLocally(ctx, certs)
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

func getCerts() ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	f, err := os.Open("./certs/ct_log_certs/certs-head.csv")
	if err != nil {
		log.Fatal(err)
	}

	// remember to close the file at the end of the program
	defer f.Close()

	csvReader := csv.NewReader(f)
	isFirstLine := true
	for {
		rec, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if !isFirstLine {
			// do something with read line
			// fmt.Printf("%+v\n", rec)

			var block *pem.Block
			block, _ = pem.Decode([]byte(rec[1]))

			switch {
			case block == nil:
				return nil, fmt.Errorf("Certificate input | no pem block")
			case block.Type != "CERTIFICATE":
				return nil, fmt.Errorf("Certificate input | contains data other than certificate")
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("Certificate input | ParseCertificate | %w", err)
			}

			certs = append(certs, cert)
		}
		isFirstLine = false
	}
	return certs, nil
}
