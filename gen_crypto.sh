#!/usr/bin/env bash

rm -rf tmp_ssl
mkdir tmp_ssl
cd tmp_ssl

IP_TARGET_NAME="127.0.0.1 ::1"

export CAROOT=$(pwd)
mkcert -cert-file comms_cert.pem -key-file comms_key.pem $IP_TARGET_NAME

head -c 128 /dev/urandom | base64 > hmac_key
