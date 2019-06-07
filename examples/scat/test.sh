#!/bin/bash

set -euo pipefail
shopt -s expand_aliases

ERROR_HAPPENED=0

error() {
	RED="\033[0;31m"
    NC='\033[0m' # No Color
    printf "${RED}${@}${NC}\n"
	ERROR_HAPPENED=1
}

# binary to hex
rbtohex() {
	od -An -vtx1 | tr -d ' \n'
}

mkdir -p tmp
cd tmp

alias scat='rustup run nightly cargo run --example scat'
alias shasum='shasum -b'

scat generate > scat_keypair_server
scat generate > scat_keypair_client

head -c 1000000 /dev/random > server_payload
head -c 1000000 /dev/random > client_payload

server_psha=$(cat server_payload | shasum)
client_psha=$(cat client_payload | shasum)

server() {
	got=$(cat server_payload \
			  | scat listen scat_keypair_server 3333 $(scat getpub scat_keypair_client) \
			  | shasum)
	if [[ $got == $client_psha ]]
	then
		echo server done
	else
		error Server Err
	fi
}

client() {
	got=$(cat client_payload \
			  | scat connect scat_keypair_client 127.0.0.1:3333 $(scat getpub scat_keypair_server) \
			  | shasum) 
	if [[ $got == $server_psha ]]
	then
		echo client done
	else
		error Client Err
	fi
}

server & ( sleep 0.1; client )

wait

exit $ERROR_HAPPENED
