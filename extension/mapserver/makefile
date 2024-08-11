.PHONY: generate_test_certs_and_RPC_SP clean

generate_test_certs_and_RPC_SP:
	@gunzip -k ./testdata/ct_monitor_certs/certs.csv.gz
	@./tools/scripts/generate_certs.sh

clean:
	@rm  -f ./certs/mapserver_certs/*
	@rm  -f ./certs/pca_certs/*
	@rm  -f ./rpc_and_sp/*
