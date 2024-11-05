#!/bin/bash

CONFIG_FILE="/cartesi-coprocessor-solver/config.toml"

if [ -n "$SECRET_KEY" ]; then
  if [ -s "$CONFIG_FILE" ]; then
    echo "" >> "$CONFIG_FILE"
  fi
  echo "secret_key = \"$SECRET_KEY\"" >> "$CONFIG_FILE"
fi

/cartesi-coprocessor-solver/cartesi-coprocessor-solver