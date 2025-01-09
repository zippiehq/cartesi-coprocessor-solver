#!/bin/bash
environment=$1
organization=$2
http_endpoint=$3
ws_endpoint=$4

app_name="cartesi-coprocessor-solver-$environment"
image="hello-world"
fly_toml="fly.$environment.toml"

echo "Setting up environment: $environment"

# Step 1: Launch the app without deploying
echo "Launching app..."
fly launch --no-deploy --config "$fly_toml" --org "$organization" || {
    echo "Error: Failed to launch"
    exit 1
}

# Step 2: Set up the database

db_name="${environment}-db-$(date +%s)"

echo "Setting up the database..."
fly postgres create --name "$db_name" \
--region "cdg" \
--org "$organization" || {
    echo "Error: Failed to create a database"
    exit 1
}

# Step 3: Attach the database to the right app
echo "Attaching the database to the app..."
fly postgres attach "$db_name" \
--app "$app_name" || {
    echo "Error: Failed to attach to database"
    exit 1
}

#step3.1 payment_phrase
echo "Generating payment phrase..."

payment_phrase=$(cast wallet nm --json | jq -r .mnemonic)
if [ -z "$payment_phrase" ]; then
    echo "Error: Failed to generate payment phrase!"
    exit 1
fi
echo "Payment phrase generated: $payment_phrase"


# Step 4: Create fly machines
for machine_num in 1 2; do
    echo "Creating machine ${machine_id} for $app_name under organization $organization..."

     flyctl machine create "$image" \
        --name "$machine_num" \
        --app "$app_name" \
        --org "$organization" \
        --region cdg \
        --verbose \
        --debug \ || {
        echo "Error: Failed to create machine ${machine_num}"
        exit 1
    }
    echo "Successfully created machine ${machine_id}."
done


FIRST_ID=$(fly machine list -a "$app_name" --json | jq -r 'sort_by(.id) | .[0].id')
SECOND_ID=$(fly machine list -a "$app_name" --json | jq -r 'sort_by(.id) | .[1].id')
echo first id: $FIRST_ID
echo second id: $SECOND_ID

#Step 4: Set secrets
for machine_id in $FIRST_ID $SECOND_ID; do

    echo "Generating wallet and setting secrets for machine ${machine_id}..."

    wallet_output=$(cast wallet new --json)
   
    wallet_file="wallet.$app_name.$machine_id.json"
    echo "$wallet_output" > "$wallet_file"

    wallet_private_key=$(echo "$wallet_output" | jq -r .[0].private_key | sed "s/0x//g")

   
    echo "Wallet for machine ${machine_id} saved to ${wallet_file}."


    config_file="config.toml.$app_name.$machine_id"
    cat > "$config_file" << EOF
http_endpoint = "$http_endpoint"
ws_endpoint = "$ws_endpoint"
registry_coordinator_address = "0x45cE5242DF4Cdd6CB925C6296732487D15216bc9"
operator_state_retriever_address = "0x4fEcf2c85D2FB1E1A35906B737Cd90bb85c05E1C"
current_first_block = 20669157
task_issuer = "0xB819BA4c5d2b64d07575ff4B30d3e0Eca219BFd5"
ruleset = "B819BA4c5d2b64d07575ff4B30d3e0Eca219BFd5"
socket = "http://localhost:3033"
secret_key = "$wallet_private_key"
payment_phrase = "$payment_phrase"
payment_token = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
max_ops = 1
EOF

    echo "Config file for machine ${machine_id} created: $config_file"

    encoded_config=$(base64 -w 0 "$config_file")
    
    
    secret_key="MACHINE_CONFIG_${machine_id}"
    
    if ! flyctl secrets set "${secret_key}=${encoded_config}" \
        --app "$app_name" \
        --stage; then
        echo "Error: Failed to set secret for machine ${machine_id}!"
        exit 1
    fi
    echo "Secret successfully set for machine ${machine_id}."
done

# Step 6: Deploy
echo "Starting deployment..."
fly deploy --config "$fly_toml" --update-only || {
    echo "Error: Deployment failed!"
    exit 1
}

# Step 7: List machines
echo "Listing all machines for app $app_name..."
machine_ids=$(flyctl machine list --app "$app_name" --json | jq -r '.[].id')

# Step 2: Update and restart each machine
for machine_id in $machine_ids; do
    
    if ! flyctl machine update --image ghcr.io/zippiehq/cartesi-coprocessor-solver:latest "$machine_id" --app "$app_name"; then
        echo "Error: Failed to update machine $machine_id!"
        exit 1
    fi
    echo "Machine $machine_id updated successfully."

    
    if ! flyctl machine restart "$machine_id" --app "$app_name"; then
        echo "Error: Failed to restart machine $machine_id!"
        exit 1
    fi
    echo "Machine $machine_id restarted successfully."
     
done
