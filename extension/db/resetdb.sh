#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

echo "Finding Trillian source code folder ..."
cd ../mapserver
TRILLIAN_RELATIVE_FOLDER=$(go list -deps -f '{{define "M"}}{{.Path}}@{{.Version}}{{end}}{{with .Module}}{{if not .Main}}{{if .Replace}}{{template "M" .Replace}}{{else}}{{template "M" .}}{{end}}{{end}}{{end}}' | grep "^github.com/google/trillian@.*$" | head -1)
TRILLIAN_FOLDER="$GOPATH/pkg/mod/${TRILLIAN_RELATIVE_FOLDER}"
cd - > /dev/null

if [ ! -d "${TRILLIAN_FOLDER}" ]; then
    echo "trillian module folder not found. Call: (go mod tidy) in the mapserver folder or try to run mapserver to download dependencies"
else
    echo "Installation found in ${TRILLIAN_FOLDER}"
    cd "${TRILLIAN_FOLDER}" && bash ./scripts/resetdb.sh --protocol TCP
fi
