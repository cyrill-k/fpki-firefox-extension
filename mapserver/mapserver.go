package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
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
	replaceDbFlag := flag.Bool("replace-db", false, "replace the content of the database with test data")
	includeCertificatesFlag := flag.Bool("include-certificates", false, "include some example certificates")
	includePoliciesFlag := flag.Bool("include-policies", true, "include some example policies")
	rootFlag := flag.String("root", "", "hexadecimal form of root value without leading '0x'")
	rootFileFlag := flag.String("rootfile", "", "path to the file storing the root in hexadecimal form without leading '0x'")
	flag.Parse()

	if len(*rootFlag) > 0 && len(*rootFileFlag) > 0 {
		log.Fatal("Can only specify either 'root' or 'rootfile'")
	} else if len(*rootFlag) == 0 && len(*rootFileFlag) == 0 && !*replaceDbFlag {
		log.Fatal("Must specify either 'root' or 'rootfile'")
	}
	var root []byte
	var err error
	if len(*rootFlag) > 0 {
		root, err = hex.DecodeString(*rootFlag)
	} else if len(*rootFileFlag) > 0 {
		dat, err := os.ReadFile(*rootFileFlag)
		if err != nil {
			log.Fatalf("Error reading file %s: %s", *rootFileFlag, err)
		}
		root, err = hex.DecodeString(string(dat))
	}
	if err != nil {
		log.Fatal("Failed to parse root value")
	}

	flag.Parse()
	if *replaceDbFlag {
		truncateTable()
		mapResponder = prepareMapServer(root, *includeCertificatesFlag, *includePoliciesFlag)
	} else {
		mapResponder = startMapServer(root)
	}

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
	fmt.Println("Mapserver ready")
}

func mapServerQueryHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case "GET":
		queryIndex := <-queryCounterChannel
		ctx, cancelF := context.WithTimeout(context.Background(), time.Minute*10)
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
		buf := new(bytes.Buffer)
		json.NewEncoder(buf).Encode(response)

		fmt.Println("[", queryIndex, "] replying for domain request: ", queriedDomain, ", size=", len(buf.String()))
		// inspectResponse(response)
		inspectDomainEntries(queryIndex, response)

	default:
		w.WriteHeader(http.StatusNotImplemented)
		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
	}
}

func inspectDomainEntries(queryIndex int, response []mapCommon.MapServerResponse) {
	for i, v := range response {
		if len(v.DomainEntryBytes) == 0 {
			fmt.Printf("[ %d ] Response %d (%s): Entry bytes is empty\n", queryIndex, i, v.Domain)
		} else {
			de, err := mapCommon.DeserializeDomainEntry(v.DomainEntryBytes)
			if err != nil {
				log.Panicln("Failed to deserialize domain entry: %s", err)
			}
			fmt.Printf("[ %d ] Response %d (%s): %d CA entries\n", queryIndex, i, v.Domain, len(de.CAEntry))
			for j, cae := range de.CAEntry {
				if cae.CurrentPC.CAName != "" {
					fmt.Printf("[ %d ] %d: %s (contains signed policy, %d domain certs)\n", queryIndex, j, cae.CAName, len(cae.DomainCerts))
				} else {
					fmt.Printf("[ %d ] %d: %s (%d domain certs)\n", queryIndex, j, cae.CAName, len(cae.DomainCerts))
				}
				var nCertChains []int
				for _, certChain := range cae.DomainCertChains {
					nCertChains = append(nCertChains, len(certChain))
				}
				fmt.Printf("[ %d ] %d: cert chain lengths: %v\n", queryIndex, i, nCertChains)
			}
		}
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

func openDb() (db *sql.DB, err error) {
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
	db, err = sql.Open("mysql", dsnString)
	return
}

func truncateTable() {
	db, err := openDb()
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

func startMapServer(root []byte) *responder.MapResponder {
	mapUpdater, err := updater.NewMapUpdater(nil, 32)
	if err != nil {
		panic(err)
	}

	// mapUpdater.GetRoot()
	fmt.Printf("root: %x\n", root)
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// get a new responder, and load an existing tree
	mapResponder, err := responder.NewMapResponder(ctx, root, 32, "./config/mapserver_config.json")
	if err != nil {
		panic(err)
	}

	return mapResponder
}

func prepareMapServer(root []byte, includeCertificates bool, includePolicies bool) *responder.MapResponder {
	mapUpdater, err := updater.NewMapUpdater(root, 32)
	if err != nil {
		panic(err)
	}

	if includeCertificates {
		certs, certChains, err := getCerts()
		if err != nil {
			panic(err)
		}

		ctx, cancelFCerts := context.WithTimeout(context.Background(), time.Minute)
		defer cancelFCerts()
		err = mapUpdater.UpdateCertsLocally(ctx, certs, certChains)
		if err != nil {
			panic(err)
		}
	}

	if includePolicies {
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
	}

	ctx, cancelFCommit := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFCommit()
	err = mapUpdater.CommitSMTChanges(ctx)
	if err != nil {
		panic(err)
	}

	root = mapUpdater.GetRoot()
	fmt.Printf("root: %x\n", root)
	err = mapUpdater.Close()
	if err != nil {
		panic(err)
	}

	// get a new responder, and load an existing tree
	mapResponder, err := responder.NewMapResponder(ctx, root, 32, "./config/mapserver_config.json")
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

func decodeCerts(encodedCerts string, separator string) ([]*x509.Certificate, [][]byte, error) {
	var certs []*x509.Certificate
	var certBytes [][]byte
	for _, encodedCert := range strings.Split(encodedCerts, separator) {
		var block *pem.Block
		block, _ = pem.Decode([]byte(encodedCert))

		switch {
		case block == nil:
			return nil, nil, fmt.Errorf("Certificate input | no pem block")
		case block.Type != "CERTIFICATE":
			return nil, nil, fmt.Errorf("Certificate input | contains data other than certificate")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("Certificate input | parsing error")
		}

		certs = append(certs, cert)
		certBytes = append(certBytes, block.Bytes)
	}
	return certs, certBytes, nil
}

func appendCertsFromCsv(path string, certColumn int, certChainColumn int, domainFilter map[string]struct{}, certs [][]byte, certChains [][][]byte) ([][]byte, [][][]byte, error) {
	f, err := os.Open(path)
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

		if !isFirstLine {
			// do something with read line
			// fmt.Printf("%+v\n", rec)

			leafCerts, leafCertBytes, err := decodeCerts(rec[certColumn], ";")
			if err != nil {
				return nil, nil, fmt.Errorf("Failed to decode certs: %s", err)
			}
			if len(leafCerts) != 1 {
				return nil, nil, fmt.Errorf("Wrong number of leaf certificates")
			}
			var domains []string
			domains = append(domains, leafCerts[0].Subject.CommonName)
			domains = append(domains, leafCerts[0].DNSNames...)
			addCertificate := false
			for _, v := range domains {
				if _, ok := domainFilter[v]; ok {
					addCertificate = true
					break
				}
			}

			if addCertificate {
				fmt.Println(domains)
				certs = append(certs, leafCertBytes[0])
				if certChainColumn != -1 {
					_, certChainBytes, err := decodeCerts(rec[certChainColumn], ";")
					if err != nil {
						return nil, nil, fmt.Errorf("Failed to decode certchain: %s", err)
					}
					certChains = append(certChains, certChainBytes)
				} else {
					certChains = append(certChains, [][]byte{})
				}
			}
		}
		isFirstLine = false
	}
	return certs, certChains, nil
}

func getCerts() ([][]byte, [][][]byte, error) {
	certsRaw := [][]byte{}
	certChainsRaw := [][][]byte{}

	type void struct{}
	var member void
	includedDomains := make(map[string]struct{})
	includedDomains["microsoft.com"] = member
	includedDomains["azure.microsoft.com"] = member
	includedDomains["bing.com"] = member
	includedDomains["google.com"] = member
	includedDomains["baidu.com"] = member
	includedDomains["amazon.com"] = member
	includedDomains["pay.amazon.com"] = member
	includedDomains["ethz.ch"] = member
	includedDomains["netsec.ethz.ch"] = member
	includedDomains["facebook.com"] = member
	includedDomains["www.facebook.com"] = member
	includedDomains["qq.com"] = member
	includedDomains["wikipedia.org"] = member

	var err error
	if certsRaw, certChainsRaw, err = appendCertsFromCsv("./testdata/ct_monitor_certs/certs.csv", 1, -1, includedDomains, certsRaw, certChainsRaw); err != nil {
		return nil, nil, err
	}
	if certsRaw, certChainsRaw, err = appendCertsFromCsv("./testdata/additional_certs/certs.csv", 0, 1, includedDomains, certsRaw, certChainsRaw); err != nil {
		return nil, nil, err
	}

	return certsRaw, certChainsRaw, nil
}
