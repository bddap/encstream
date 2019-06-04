#!/bin/bash

set -euo pipefail
shopt -s expand_aliases

panic(){
    RED="\033[0;31m"
    NC='\033[0m' # No Color

    printf "${RED}${@}${NC}\n"
	exit 1
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

server_payload=$(head -c 10000 /dev/random | rbtohex)
client_payload=$(head -c 10000 /dev/random | rbtohex)

server() {
	got=$(echo -n $server_payload \
			| scat listen scat_keypair_server 3333 $(scat getpub scat_keypair_client))
	if [[ $got == $client_payload ]]
	then
		echo server done
	else
		panic Server Err
	fi
}

client() {
	got=$(echo -n $client_payload \
			  | scat connect scat_keypair_client 127.0.0.1:3333 $(scat getpub scat_keypair_server))
	if [[ $got == $server_payload ]]
	then
		echo client done
	else
		panic Client Err
	fi
}

server &
spid=$!

sleep 0.1; # feed the race condition

client &
cpid=$!

wait $spid
wait $cpid
