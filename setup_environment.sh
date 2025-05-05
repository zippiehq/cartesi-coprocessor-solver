#!/bin/bash
environment=$1
organization=$2
http_endpoint=$3
ws_endpoint=$4

app_name="cartesi-coprocessor-solver-$environment"
image="hello-world"
fly_toml="fly.$environment.toml"

echo "Setting up environment: $environment"

# Step 1: Set up the database first
db_name="${environment}-db-$(date +%s)"

echo "Setting up the database..."
fly postgres create --name "$db_name" \
    --region "cdg" \
    --vm-size "shared-cpu-1x" --initial-cluster-size 2 \
    --org "$organization" || {
    echo "Error: Failed to create a database"
    exit 1
}



# Step 2: Launch the app without deploying
echo "Launching app..."
fly launch --no-deploy --config "$fly_toml" --org "$organization" || {
    echo "Error: Failed to launch"
    exit 1
}

# Attach the database to the app
echo "Attaching the database to the app..."
connection_url=$(fly postgres attach "$db_name" --app "$app_name")

echo "$connection_url"

database_url=$(echo "$connection_url" | grep -oP 'DATABASE_URL=.*' | sed 's/DATABASE_URL=//')

# Setting up the storage
echo "Creating a bucket..."
storage_output=$(fly storage create -n cartesi-data-$environment -a "$app_name" -o "$organization" | grep ':')
echo $storage_output

AWS_ENDPOINT_URL_S3=$(echo "$storage_output" | grep 'AWS_ENDPOINT_URL_S3' | cut -d':' -f2 | tr -d ' ')
AWS_ACCESS_KEY_ID=$(echo "$storage_output" | grep 'AWS_ACCESS_KEY_ID' | cut -d':' -f2 | tr -d ' ')
AWS_SECRET_ACCESS_KEY=$(echo "$storage_output" | grep 'AWS_SECRET_ACCESS_KEY' | cut -d':' -f2 | tr -d ' ')
BUCKET_NAME=$(echo "$storage_output" | grep 'BUCKET_NAME' | cut -d':' -f2 | tr -d ' ')
AWS_REGION=$(echo "$storage_output" | grep 'AWS_REGION' | cut -d':' -f2 | tr -d ' ')

# Step 3: Generate payment phrase
echo "Generating payment phrase..."
payment_phrase=$(cast wallet nm --json | jq -r .mnemonic)
if [ -z "$payment_phrase" ]; then
    echo "Error: Failed to generate payment phrase!"
    exit 1
fi
echo "Payment phrase generated: $payment_phrase"


# Store the secrets before deployment
echo "Setting up secrets for deployment..."
flyctl secrets set \
    AWS_ENDPOINT_URL_S3="$AWS_ENDPOINT_URL_S3" \
    AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
    AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    BUCKET_NAME="$BUCKET_NAME" \
    AWS_REGION="$AWS_REGION" \
    --app "$app_name" || {
    echo "Error: Failed to set secrets!"
    exit 1
}

# Step 4: Deploy and scale machines to exactly 2
echo "Deploying app..."
fly deploy --config "$fly_toml" --update-only || {
    echo "Error: Deployment failed!"
    exit 1
}

echo "Ensuring only 2 machines are running..."
fly scale count 2 --app "$app_name" || {
    echo "Error: Failed to scale machines to 2"
    exit 1
}

# Step 5: List machines
echo "Listing all machines for app $app_name..."
machine_ids=$(flyctl machine list --app "$app_name" --json | jq -r '.[0:2] | .[].id')

# Step 6: Set secrets for each machine
for machine_id in $machine_ids; do
    echo "Generating wallet and setting secrets for machine ${machine_id}..."
    
    wallet_output=$(cast wallet new --json)
    wallet_file="wallet.$app_name.$machine_id.json"
    echo "$wallet_output" >"$wallet_file"

    wallet_private_key=$(echo "$wallet_output" | jq -r .[0].private_key | sed "s/0x//g")

    filename="deploy_config.${environment}.env"
    . "$filename"

    config_file="config.toml.$app_name.$machine_id"
    cat >"$config_file" <<EOF
l1_http_endpoint = "$http_endpoint"
l2_http_endpoint = "$http_endpoint"
l1_ws_endpoint = "$ws_endpoint"
l2_ws_endpoint = "$ws_endpoint"
registry_coordinator_address = "$registry_coordinator_address"
operator_state_retriever_address = "$operator_state_retriever_address"
current_first_block = 3750302
task_issuer = "$task_issuer"
callback_address = "$callback_address"
ruleset = "$ruleset"
socket = "http://operator:3033"
secret_key = "$wallet_private_key"
payment_phrase = "$payment_phrase"
postgre_connect_request = "$database_url_1"
payment_token = "0x94373a4919b3240d86ea41593d5eba789fef3848" 
max_ops = 1
l2Sender = "0x82e01223d51Eb87e16A03E24687EDF0F294da6f1"
eth_value = "0"
senderData = [0]
listen_network = "L1"
l2_coprocessor_address = "0xCD8a1C3ba11CF5ECfa6267617243239504a98d90"
l1_coprocessor_address = "0x7969c5eD335650692Bc04293B07F5BF2e7A673C0"
EOF
    
    encoded_config=$(base64 -w 0 "$config_file")
    secret_key="MACHINE_CONFIG_${machine_id}"
    
    if ! flyctl secrets set "${secret_key}=${encoded_config}" --app "$app_name" --stage; then
        echo "Error: Failed to set secret for machine ${machine_id}!"
        exit 1
    fi
    echo "Secret successfully set for machine ${machine_id}."
done


# Step : Update and restart each machine
for machine_id in $machine_ids; do

    echo "Updating machine ${machine_id}..."
    secret_key="MACHINE_CONFIG_${machine_id}"

    if ! flyctl machine update "$machine_id" \
        --app "$app_name" \
        --image "ghcr.io/zippiehq/cartesi-coprocessor-solver:$image_version" \
        --file-secret "/run/secrets/config.toml.${machine_id}=${secret_key}" \
        --skip-start; then
        echo "Error: Failed to update machine ${machine_id}!"
        exit 1
    fi

    echo "Machine $machine_id updated successfully."

    echo "starting machine ${machine_id}..."
    flyctl machine start "$machine_id" --app "$app_name" || {
        echo "Failed to start machine ${machine_id}."
        exit 1
    }

    echo "Machine ${machine_id} updated, restarted, and verified successfully."
done
