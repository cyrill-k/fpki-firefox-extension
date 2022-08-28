go run ./tools/server_certs_generater/cert_generater.go

echo "map server and pca certs generated"

go build -o logserver_exec ./tools/logserver/logserver_exec.go
go build -o logsigner_exec ./tools/logsigner/logsigner_exec.go

./logserver_exec >/dev/null& 
./logsigner_exec >/dev/null& 

sleep 2

echo "started policy logs"

go run ./tools/policy_generater.go

# looks like kill once is not enough... do this for now
pkill -f logserver_exec
pkill -f logsigner_exec
pkill -f logserver_exec
pkill -f logsigner_exec

rm logserver_exec
rm logsigner_exec

echo "finished"