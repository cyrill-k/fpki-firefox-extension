#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

echo "Granting user 'test' the necessary privileges ..."
cat ./grant_user_privileges.sql | mysql -u ${MYSQL_ROOT_USER:-root} -p${MYSQL_ROOT_PASSWORD:-root} -P ${MYSQL_PORT:-3306} --protocol TCP
