#!/bin/bash

CONFIG_FILE="/cartesi-coprocessor-solver/config.toml"
 
if [ -z "$RUST_LOG" ]; then
	export RUST_LOG=info
fi

if [ -n "$FLY_MACHINE_ID" ]; then
	if [ -e /run/secrets/config.toml.$FLY_MACHINE_ID ]; then
		echo "Using fly machine ID specific config"
		cp /run/secrets/config.toml.$FLY_MACHINE_ID $CONFIG_FILE
	else
        	echo "Config file /run/secrets/config.toml.$FLY_MACHINE_ID not found" >&2
        	exit 1
       	fi
fi

/cartesi-coprocessor-solver/cartesi-coprocessor-solver