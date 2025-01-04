#!/bin/bash

CONFIG_FILE="/cartesi-coprocessor-solver/config.toml"

get_secret_value() {
  local secret_name=$1
  local default_value=$2
  local secret_path="/run/secrets/${secret_name}"

  if [ -f "$secret_path" ]; then
   
    cat "$secret_path"
  else
    
    printf "%s" "$default_value"
  fi
}

y
add_to_config() {
  local key=$1
  local value=$2

  
  if [ -n "$value" ]; then
    if [ -s "$CONFIG_FILE" ]; then
      echo "" >> "$CONFIG_FILE"
    fi
    echo "$key = \"$value\"" >> "$CONFIG_FILE"
  fi
}


HTTP_ENDPOINT=$(get_secret_value "HTTP_ENDPOINT" "$HTTP_ENDPOINT")
add_to_config "http_endpoint" "$HTTP_ENDPOINT"


WS_ENDPOINT=$(get_secret_value "WS_ENDPOINT" "$WS_ENDPOINT")
add_to_config "ws_endpoint" "$WS_ENDPOINT"

y
SECRET_KEY=$(get_secret_value "SECRET_KEY" "$SECRET_KEY")
add_to_config "secret_key" "$SECRET_KEY"


PAYMENT_PHRASE=$(get_secret_value "PAYMENT_PHRASE" "$PAYMENT_PHRASE")
add_to_config "payment_phrase" "$PAYMENT_PHRASE"


POSTGRE_CONNECT_REQUEST=$(get_secret_value "POSTGRE_CONNECT_REQUEST" "$POSTGRE_CONNECT_REQUEST")
add_to_config "postgre_connect_request" "$POSTGRE_CONNECT_REQUEST"

/cartesi-coprocessor-solver/cartesi-coprocessor-solver