go run ./tools/server_certs_generater/cert_generater.go

echo "map server and pca certs generated"

go build -o logserver_exec ./tools/logserver/logserver_exec.go
go build -o logsigner_exec ./tools/logsigner/logsigner_exec.go

./logserver_exec --mysql_uri "test:zaphod@tcp(127.0.0.1:3307)/test" >/dev/null& 
./logsigner_exec --mysql_uri "test:zaphod@tcp(127.0.0.1:3307)/test" >/dev/null& 

sleep 2

echo "started policy logs"

POLICY_GENERATION_STATUS="succeed"

go run ./tools/policy_generater.go
if [ $? -ne 0 ]
then
	POLICY_GENERATION_STATUS="failed"
fi

# looks like kill once is not enough... do this for now
pkill -f logserver_exec
pkill -f logsigner_exec
pkill -f logserver_exec
pkill -f logsigner_exec

rm logserver_exec
rm logsigner_exec

# clear

if [ $POLICY_GENERATION_STATUS != "succeed" ] 
then
	echo "failed"
else 
    echo "succeed!"
fi
