use alloy::signers::k256::elliptic_curve::consts;
use alloy::signers::k256::SecretKey;
use alloy_contract::Event;
use alloy_primitives::U256;
use alloy_primitives::{bytes, keccak256, Address, FixedBytes, Keccak256, TxHash, B256};
use alloy_provider::{Identity, Provider, ProviderBuilder, ReqwestProvider};
use alloy_rpc_types_eth::Filter;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner};
use alloy_sol_types::sol;
use ark_serialize::CanonicalDeserialize;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use eigen_client_avsregistry::reader::AvsRegistryChainReader;
use eigen_crypto_bls::{
    convert_to_bls_checker_g1_point, convert_to_bls_checker_g2_point, Signature,
};
use eigen_logging::{log_level::LogLevel, tracing_logger::TracingLogger};
use eigen_services_avsregistry::{chaincaller::AvsRegistryServiceChainCaller, AvsRegistryService};
use eigen_services_blsaggregation::bls_agg::{BlsAggregationServiceResponse, BlsAggregatorService};
use eigen_services_operatorsinfo::operatorsinfo_inmemory::OperatorInfoServiceInMemory;
use eigen_types::operator::OperatorAvsState;
use eigen_utils::{
    get_provider,
    iblssignaturechecker::{
        IBLSSignatureChecker::{self, NonSignerStakesAndSignature},
        BN254::G1Point,
    },
};
use futures_util::FutureExt;
use futures_util::{StreamExt, TryStreamExt};
use hex::FromHex;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server, StatusCode, Uri,
};
use serde::Deserialize;
use std::error::Error;
use std::io::Bytes;
use std::str::FromStr;
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    sync::Mutex,
    task::{self, JoinHandle},
};
use tokio_postgres::{AsyncMessage, NoTls};
use tokio_util::sync::CancellationToken;
use ICoprocessor::TaskIssued;
mod outputs_merkle;
use alloy_network::EthereumWallet;
use alloy_provider::fillers::{
    BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller,
};
use futures_util::stream;
use tokio_postgres::types::{FromSql, ToSql};

const HEIGHT: usize = 63;
const TASK_INDEX: u32 = 1;
#[derive(Deserialize, Clone)]
struct Config {
    l1_http_endpoint: String,
    l1_ws_endpoint: String,
    l2_http_endpoint: String,
    l2_ws_endpoint: String,
    l2_coprocessor_address: String,
    l1_coprocessor_address: String,
    registry_coordinator_address: Address,
    operator_state_retriever_address: Address,
    current_first_block: u64,
    task_issuer: Address,
    ruleset: String,
    max_ops: u64,
    socket: String,
    secret_key: String,
    payment_phrase: String,
    postgre_connect_request: String,
    payment_token: Address,
    listen_network: String,
    l2Sender: Address,
    senderData: Vec<u8>,
    eth_value: String,
}
#[derive(Debug, ToSql, FromSql, PartialEq)]
enum task_status {
    handled,
    in_progress,
    waits_for_handling,
    sent_to_l1,
    finalized_on_l2,
}
#[tokio::main]
async fn main() {
    let config_string = std::fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&config_string).unwrap();
    let manager =
        PostgresConnectionManager::new(config.postgre_connect_request.parse().unwrap(), NoTls);

    let pool = Pool::builder().build(manager).await.unwrap();
    let client = pool.get().await.unwrap();
    client
        .execute(
            "
            DO $$ BEGIN
                CREATE TYPE task_status AS ENUM ('handled', 'in_progress', 'waits_for_handling' , 'sent_to_l1', 'finalized_on_l2');
            EXCEPTION
                WHEN duplicate_object THEN null;
            END $$;
       ",
            &[],
        )
        .await
        .unwrap();
    client
        .batch_execute(
            "
        CREATE TABLE IF NOT EXISTS issued_tasks (
            id SERIAL PRIMARY KEY,
            machineHash BYTEA,
            input BYTEA,
            callback BYTEA,
            status task_status
        )
 ",
        )
        .await
        .unwrap();
    client
        .batch_execute(
            "
        CREATE UNIQUE INDEX IF NOT EXISTS unique_machine_input_callback
        ON issued_tasks ((machineHash || input || callback))
",
        )
        .await
        .unwrap();

    client
        .batch_execute("CREATE TABLE IF NOT EXISTS machine_hashes (id SERIAL PRIMARY KEY, machine_hash BYTEA UNIQUE)").await.unwrap();

    client
        .batch_execute(
            "
        CREATE TABLE IF NOT EXISTS finalization_data (
            resp_responseHash BYTEA UNIQUE,
            resp_ruleSet BYTEA,
            resp_machineHash BYTEA,
            resp_payloadHash BYTEA,
            resp_outputMerkle BYTEA,
            callback_address BYTEA,
            outputs BYTEA[]
        )
    ",
        )
        .await
        .unwrap();

    println!("Starting solver..");
    let arc_ws_endpoint = Arc::new(config.l1_ws_endpoint.clone());

    let tracing_logger =
        TracingLogger::new_text_logger(false, String::from(""), LogLevel::Debug, false);
    let avs_registry_reader = AvsRegistryChainReader::new(
        tracing_logger.clone(),
        config.registry_coordinator_address,
        config.operator_state_retriever_address,
        config.l1_http_endpoint.clone(),
    )
    .await
    .unwrap();

    let operators_info = OperatorInfoServiceInMemory::new(
        tracing_logger.clone(),
        avs_registry_reader.clone(),
        config.l1_ws_endpoint.clone(),
    )
    .await;
    let avs_registry_service =
        AvsRegistryServiceChainCaller::new(avs_registry_reader, operators_info.clone());

    let cancellation_token = CancellationToken::new();
    let operators_info_clone = Arc::new(operators_info.clone());
    let token_clone = cancellation_token.clone();
    let provider =
        alloy_provider::ProviderBuilder::new().on_http(config.l1_http_endpoint.parse().unwrap());
    let current_block_num = provider.get_block_number().await.unwrap();
    println!("current_block_num {:?}", current_block_num);

    task::spawn({
        let arc_operators_info = operators_info_clone.clone();
        async move {
            arc_operators_info
                .start_service(&token_clone, config.current_first_block, current_block_num)
                .await
                .unwrap();
        }
    });

    operators_info.past_querying_finished.notified().await;
    let sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let current_last_block = Arc::new(Mutex::new(config.current_first_block));
    let querying_thread = query_operator_socket_update(
        config.l1_ws_endpoint.clone(),
        sockets_map.clone(),
        config.current_first_block,
        current_last_block.clone(),
        config.registry_coordinator_address,
    );

    let ruleset = config.ruleset.clone();
    let max_ops = config.max_ops.clone();
    let addr: SocketAddr = ([0, 0, 0, 0], 3034).into();
    let service = make_service_fn(|_| {
        let avs_registry_service = avs_registry_service.clone();
        let ws_endpoint = config.l1_ws_endpoint.clone();
        let http_endpoint = config.l1_http_endpoint.clone();

        let config_socket = config.socket.clone();
        let pool = pool.clone();
        let sockets_map = sockets_map.clone();
        let ruleset = ruleset.clone();
        let secret_key = config.secret_key.clone();
        let payment_phrase = config.payment_phrase.clone();

        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let avs_registry_service = avs_registry_service.clone();
                let ws_endpoint = ws_endpoint.clone();
                let http_endpoint = http_endpoint.clone();

                let config_socket = config_socket.clone();
                let pool = pool.clone();

                let sockets_map = sockets_map.clone();
                let ruleset = ruleset.clone();
                let secret_key = secret_key.clone();
                let payment_phrase = payment_phrase.clone();

                async move {
                    let path = req.uri().path().to_owned();
                    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

                    match (req.method().clone(), &segments as &[&str]) {
                        (hyper::Method::POST, ["eth_address", machine_hash]) => {
                            let machine_hash = match B256::from_hex(&machine_hash) {
                                Ok(hash) => hash,
                                Err(err) => {
                                    let json_error = serde_json::json!({
                                        "error": err.to_string()
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::BAD_REQUEST)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            };

                            let generated_address =
                                generate_eth_address(pool, machine_hash, payment_phrase).await;
                            let json_response = serde_json::json!({
                                "eth_address": generated_address
                            });
                            let json_response = serde_json::to_string(&json_response).unwrap();
                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Body::from(json_response))
                                .unwrap();
                            return Ok::<_, Infallible>(response);
                        }
                        (hyper::Method::POST, ["issue_task", machine_hash, callback]) => {
                            let input = hyper::body::to_bytes(req.into_body())
                                .await
                                .unwrap()
                                .to_vec();
                            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);

                            let ws_provider = alloy_provider::ProviderBuilder::new()
                                .on_ws(ws_connect)
                                .await
                                .unwrap();

                            let current_block_number =
                                ws_provider.clone().get_block_number().await.unwrap();
                            let quorum_nums = [0];
                            let quorum_threshold_percentages = vec![100_u8];
                            let time_to_expiry = Duration::from_secs(10);

                            match avs_registry_service
                                .clone()
                                .get_operators_avs_state_at_block(
                                    current_block_number as u32,
                                    &quorum_nums,
                                )
                                .await
                            {
                                Ok(operators) => {
                                    let task_issued = TaskIssued {
                                        machineHash: B256::from_hex(&machine_hash).unwrap(),
                                        input: input.into(),
                                        callback: Address::parse_checksummed(callback, None)
                                            .expect("can't convert callback to Address"),
                                    };
                                    let bls_agg_response = handle_task_issued_operator(
                                        operators,
                                        true,
                                        sockets_map.clone(),
                                        config_socket.clone(),
                                        task_issued.clone(),
                                        avs_registry_service.clone(),
                                        time_to_expiry,
                                        ruleset.clone(),
                                        max_ops,
                                        current_block_num,
                                        quorum_nums.to_vec(),
                                        quorum_threshold_percentages.clone(),
                                    )
                                    .await;
                                    match bls_agg_response {
                                        Ok(service_response) => {
                                            let json_responses = serde_json::json!({
                                                "service_response": service_response,
                                            });
                                            let json_responses =
                                                serde_json::to_string(&json_responses).unwrap();
                                            let response = Response::builder()
                                                .status(StatusCode::OK)
                                                .body(Body::from(json_responses))
                                                .unwrap();

                                            return Ok::<_, Infallible>(response);
                                        }
                                        Err(err) => {
                                            //handles the case when proofs weren't proved successfully
                                            let json_error = serde_json::json!({
                                                "error": err.to_string()
                                            });
                                            let json_error =
                                                serde_json::to_string(&json_error).unwrap();
                                            let response = Response::builder()
                                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(Body::from(json_error))
                                                .unwrap();
                                            return Ok::<_, Infallible>(response);
                                        }
                                    }
                                }
                                Err(err) => {
                                    let json_error = serde_json::json!({
                                        "error": format!("Failed to get operators: {:?}", err)
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            }
                        }
                        (hyper::Method::GET, ["get_preimage", hash_type, hash]) => {
                            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
                            let ws_provider = alloy_provider::ProviderBuilder::new()
                                .on_ws(ws_connect)
                                .await
                                .unwrap();
                            let current_block_number =
                                ws_provider.clone().get_block_number().await.unwrap();
                            let quorum_nums = [0];

                            match avs_registry_service
                                .clone()
                                .get_operators_avs_state_at_block(
                                    current_block_number as u32,
                                    &quorum_nums,
                                )
                                .await
                            {
                                Ok(operators) => {
                                    for operator in operators {
                                        let operator_id = operator.1.operator_id;
                                        let sockets_map = sockets_map.lock().await;
                                        match sockets_map.get(&operator_id.to_vec()) {
                                            Some(mut socket) => {
                                                if socket == "Not Needed" {
                                                    socket = &config_socket;
                                                }
                                                let get_preimage_request = Request::builder()
                                                    .method("GET")
                                                    .uri(format!(
                                                        "{}/get_preimage/{}/{}",
                                                        socket, hash_type, hash
                                                    ))
                                                    .body(Body::empty())
                                                    .unwrap();

                                                let http_client = Client::new();

                                                let preimage_response = http_client
                                                    .request(get_preimage_request)
                                                    .await
                                                    .unwrap();

                                                let preimage_response_bytes =
                                                    hyper::body::to_bytes(preimage_response)
                                                        .await
                                                        .unwrap()
                                                        .to_vec();

                                                if check_preimage_hash(
                                                    &hex::decode(hash).unwrap(),
                                                    &preimage_response_bytes,
                                                )
                                                .is_ok()
                                                {
                                                    let response = Response::builder()
                                                        .status(StatusCode::OK)
                                                        .body(Body::from(preimage_response_bytes))
                                                        .unwrap();

                                                    return Ok::<_, Infallible>(response);
                                                }
                                            }
                                            None => {
                                                let json_error = serde_json::json!({
                                                    "error": format!("No socket for operator_id = {:?}", hex::encode(operator_id.to_vec()))
                                                });
                                                let json_error =
                                                    serde_json::to_string(&json_error).unwrap();
                                                let response = Response::builder()
                                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                    .body(Body::from(json_error))
                                                    .unwrap();

                                                return Ok::<_, Infallible>(response);
                                            }
                                        }
                                    }
                                }
                                Err(err) => {
                                    let json_error = serde_json::json!({
                                        "error": format!("Failed to get operators: {:?}", err)
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            }
                            let json_error = serde_json::json!({
                                "error": "Preimage wasn't found",
                            });
                            let json_error = serde_json::to_string(&json_error).unwrap();

                            let response = Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Body::from(json_error))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                        (hyper::Method::POST, ["ensure", cid_str, machine_hash, size_str]) => {
                            let generated_address = generate_eth_address(
                                pool.clone(),
                                B256::from_hex(&machine_hash).unwrap(),
                                payment_phrase,
                            )
                            .await;
                            let secret_key =
                                SecretKey::from_slice(&hex::decode(secret_key.clone()).unwrap())
                                    .unwrap();
                            let signer = PrivateKeySigner::from(secret_key);
                            let wallet = EthereumWallet::from(signer);
                            let provider = ProviderBuilder::new()
                                .with_recommended_fillers()
                                .wallet(wallet)
                                .on_http(http_endpoint.parse().unwrap());
                            let contract = IERC20::new(config.payment_token, &provider);
                            let balance_caller = contract.balanceOf(generated_address);
                            match balance_caller.call().await {
                                Ok(balance) => {
                                    println!("balanceOf {:?} = {:?}", generated_address, balance);
                                }
                                Err(err) => {
                                    println!("Transaction wasn't sent successfully: {err}");
                                }
                            }
                            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
                            let ws_provider = alloy_provider::ProviderBuilder::new()
                                .on_ws(ws_connect)
                                .await
                                .unwrap();
                            let current_block_number =
                                ws_provider.clone().get_block_number().await.unwrap();
                            let quorum_nums = [0];

                            match avs_registry_service
                                .clone()
                                .get_operators_avs_state_at_block(
                                    current_block_number as u32,
                                    &quorum_nums,
                                )
                                .await
                            {
                                Ok(operators) => {
                                    let mut states_for_operators: HashMap<String, String> =
                                        HashMap::new();
                                    for operator in operators {
                                        let operator_id = operator.1.operator_id;
                                        let sockets_map = sockets_map.lock().await;
                                        match sockets_map.get(&operator_id.to_vec()) {
                                            Some(mut socket) => {
                                                if socket == "Not Needed" {
                                                    socket = &config_socket;
                                                }

                                                let request = Request::builder()
                                                    .method("POST")
                                                    .header("X-Ruleset", &ruleset)
                                                    .uri(format!(
                                                        "{}/ensure/{}/{}/{}",
                                                        socket, cid_str, machine_hash, size_str
                                                    ))
                                                    .body(Body::empty())
                                                    .unwrap();
                                                println!(
                                                    "{}/ensure/{}/{}/{}",
                                                    socket, cid_str, machine_hash, size_str
                                                );
                                                let client = Client::new();
                                                let response =
                                                    client.request(request).await.unwrap();
                                                let response_json =
                                                    serde_json::from_slice::<serde_json::Value>(
                                                        &hyper::body::to_bytes(response)
                                                            .await
                                                            .expect(
                                                                format!(
                                                                    "Error requesting {}/ensure/{}/{}/{}",
                                                                    socket,
                                                                    cid_str,
                                                                    machine_hash,
                                                                    size_str
                                                                )
                                                                .as_str(),
                                                            )
                                                            .to_vec(),
                                                    )
                                                    .unwrap();
                                                match response_json.get("state") {
                                                    Some(serde_json::Value::String(state)) => {
                                                        states_for_operators.insert(
                                                            hex::encode(operator_id.to_vec()),
                                                            state.to_string(),
                                                        );
                                                    }
                                                    _ => {
                                                        panic!("No state found in request {}/ensure/{}/{}/{} response", socket,
                                                        cid_str,
                                                        machine_hash,
                                                        size_str);
                                                    }
                                                };
                                            }
                                            None => {
                                                let json_error = serde_json::json!({
                                                    "error": format!("No socket for operator_id = {:?}", hex::encode(operator_id.to_vec()))
                                                });
                                                let json_error =
                                                    serde_json::to_string(&json_error).unwrap();
                                                let response = Response::builder()
                                                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                                                    .body(Body::from(json_error))
                                                    .unwrap();

                                                return Ok::<_, Infallible>(response);
                                            }
                                        }
                                    }
                                    let json_responses = serde_json::json!({
                                        "operator_ids_with_states": states_for_operators,
                                    });
                                    let json_responses =
                                        serde_json::to_string(&json_responses).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Body::from(json_responses))
                                        .unwrap();

                                    return Ok::<_, Infallible>(response);
                                }
                                Err(err) => {
                                    let json_error = serde_json::json!({
                                        "error": format!("Failed to get operators: {:?}", err)
                                    });
                                    let json_error = serde_json::to_string(&json_error).unwrap();
                                    let response = Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(Body::from(json_error))
                                        .unwrap();
                                    return Ok::<_, Infallible>(response);
                                }
                            }
                        }
                        (hyper::Method::GET, ["health"]) => {
                            let json_request = r#"{"healthy": "true"}"#;
                            let response = Response::new(Body::from(json_request));
                            return Ok::<_, Infallible>(response);
                        }
                        _ => {
                            let json_error = serde_json::json!({
                                "error": "unknown request",
                            });
                            let json_error = serde_json::to_string(&json_error).unwrap();
                            let response = Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Body::from(json_error))
                                .unwrap();

                            return Ok::<_, Infallible>(response);
                        }
                    }
                }
            }))
        }
    });
    let server = Server::bind(&addr).serve(Box::new(service));
    println!("Server is listening on {}", addr);
    let _ = querying_thread.await;
    println!("Finished OperatorSocketUpdate querying");

    if config.listen_network == "optimism" {
        subscribe_task_issued_l2(
            config.l2_ws_endpoint.clone(),
            config.l2_http_endpoint.clone(),
            config.payment_token.clone(),
            config.l2_coprocessor_address.clone(),
            pool.clone(),
            config.secret_key.clone(),
            config.payment_phrase.clone(),
        );

        new_task_issued_handler_l2(
            config.l2_ws_endpoint.clone(),
            config.l1_http_endpoint.clone(),
            config.l1_coprocessor_address.clone(),
            config.l2_coprocessor_address.clone(),
            avs_registry_service.clone(),
            sockets_map.clone(),
            config.socket.clone(),
            config.ruleset.clone(),
            config.max_ops,
            current_block_num,
            config.secret_key.clone(),
            config.task_issuer,
            pool.clone(),
            config.postgre_connect_request,
            config.l2Sender,
            config.senderData,
            config.eth_value,
        );

        subscribe_task_completed_l2(
            config.l2_ws_endpoint.clone(),
            config.l2_http_endpoint.clone(),
            Address::from_str(&config.l2_coprocessor_address).unwrap(),
            config.secret_key.clone(),
            pool.clone(),
        )
        .await;
    } else {
        //Subscriber which inserts new tasks into the DB
        subscribe_task_issued_l1(
            config.l1_ws_endpoint.clone(),
            config.l1_http_endpoint.clone(),
            config.payment_token.clone(),
            config.task_issuer.clone(),
            pool.clone(),
            config.secret_key.clone(),
            config.payment_phrase.clone(),
        );
        //Subscriber which handles new tasks received from DB
        new_task_issued_handler_l1(
            config.l1_ws_endpoint.clone(),
            config.l1_http_endpoint.clone(),
            avs_registry_service.clone(),
            sockets_map.clone(),
            config.socket.clone(),
            config.ruleset.clone(),
            config.max_ops,
            current_block_num,
            config.secret_key.clone(),
            config.task_issuer,
            pool.clone(),
            config.postgre_connect_request.clone(),
        );
        println!("listening on l1");
    }

    subscribe_operator_socket_update(
        arc_ws_endpoint,
        sockets_map.clone(),
        config.registry_coordinator_address,
        current_last_block.clone(),
    );
    server.await.unwrap();
}

fn query_operator_socket_update(
    ws_endpoint: String,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    current_first_block: u64,
    current_last_block: Arc<Mutex<u64>>,
    registry_coordinator_address: Address,
) -> JoinHandle<()> {
    task::spawn({
        let sockets_map = Arc::clone(&sockets_map);
        let current_last_block = Arc::clone(&current_last_block);
        async move {
            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();

            let last_block = ws_provider.clone().get_block_number().await.unwrap();
            let mut current_last_block = current_last_block.lock().await;
            let mut current_first_block = current_first_block;

            while current_first_block <= last_block {
                *current_last_block = if current_first_block + 10000 < last_block {
                    current_first_block + 10000
                } else {
                    last_block
                };

                let event_filter = Filter::new()
                    .address(registry_coordinator_address)
                    .from_block(current_first_block.clone())
                    .to_block(current_last_block.clone())
                    .event("OperatorSocketUpdate(bytes32,string)");

                let event: Event<_, _, ISocketUpdater::OperatorSocketUpdate, _> =
                    Event::new(ws_provider.clone(), event_filter);
                let filtered_events = event.query().await.unwrap();

                for (operator_socket_update, log) in filtered_events {
                    println!(
                        "stream_event operator socket update {:?}",
                        operator_socket_update
                    );
                    println!("stream_event operator socket update log {:?}", log);
                    sockets_map.lock().await.insert(
                        operator_socket_update.operatorId.as_slice().to_vec(),
                        operator_socket_update.socket,
                    );
                }
                if current_first_block == *current_last_block {
                    break;
                }
                current_first_block = current_last_block.clone() + 1;
            }
        }
    })
}

async fn handle_task_issued_operator(
    operators: HashMap<FixedBytes<32>, OperatorAvsState>,
    generate_proofs: bool,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    config_socket: String,
    stream_event: TaskIssued,
    avs_registry_service: AvsRegistryServiceChainCaller<
        AvsRegistryChainReader,
        OperatorInfoServiceInMemory,
    >,
    time_to_expiry: Duration,
    ruleset: String,
    max_ops: u64,
    current_block_num: u64,
    quorum_nums: Vec<u8>,
    quorum_threshold_percentages: Vec<u8>,
) -> Result<
    (
        BlsAggregationServiceResponse,
        HashMap<alloy_primitives::FixedBytes<32>, Vec<(u16, Vec<u8>)>>,
    ),
    Box<dyn std::error::Error>,
> {
    let mut bls_agg_service = BlsAggregatorService::new(avs_registry_service.clone());
    let mut response_digest_map = HashMap::new();
    for operator in operators {
        bls_agg_service = BlsAggregatorService::new(avs_registry_service.clone());
        let operator_id = operator.1.operator_id;
        let sockets_map = sockets_map.lock().await;
        match sockets_map.get(&operator_id.to_vec()) {
            Some(mut socket) => {
                if socket == "Not Needed" {
                    socket = &config_socket;
                }

                let request = Request::builder()
                    .method("POST")
                    .header("X-Ruleset", &ruleset)
                    .header("X-Max-Ops", max_ops)
                    .uri(format!("{}/classic/{:x}", socket, stream_event.machineHash))
                    .body(Body::from(stream_event.input.to_vec()))?;
                println!("{}/classic/{:x}", socket, stream_event.machineHash);
                let client = Client::new();
                let response = client.request(request).await?;
                let response_json = serde_json::from_slice::<serde_json::Value>(
                    &hyper::body::to_bytes(response).await?.to_vec(),
                )?;

                let response_signature: String = match response_json.get("signature") {
                    Some(serde_json::Value::String(sign)) => sign.to_string(),
                    _ => {
                        return Err(format!("No signature found in request response").into());
                    }
                };

                let finish_callback: Vec<serde_json::Value> = match response_json
                    .get("finish_callback")
                {
                    Some(serde_json::Value::Array(finish_callback)) => {
                        if finish_callback.len() == 2
                            && finish_callback[0].is_number()
                            && finish_callback[1].is_array()
                        {
                            finish_callback[1].as_array().unwrap().to_vec()
                        } else {
                            finish_callback.to_vec()
                        }
                    }
                    _ => {
                        return Err(format!("No finish_callback found in request response").into());
                    }
                };
                let finish_result = extract_number_array(finish_callback);
                let outputs_vector: Vec<(u16, Vec<u8>)> =
                    match response_json.get("outputs_callback_vector") {
                        Some(outputs_callback) => serde_json::from_value(outputs_callback.clone())?,
                        _ => {
                            return Err(format!(
                                "No outputs_callback_vector found in request response"
                            )
                            .into());
                        }
                    };
                if generate_proofs {
                    let mut keccak_outputs = Vec::new();

                    for output in outputs_vector.clone() {
                        let mut hasher = Keccak256::new();
                        hasher.update(output.1.clone());
                        keccak_outputs.push(hasher.finalize());
                    }

                    let proofs = outputs_merkle::create_proofs(keccak_outputs, HEIGHT)?;

                    if proofs.0.to_vec() != finish_result {
                        return Err(format!("Outputs weren't proven successfully").into());
                    }
                }

                let signature_bytes = hex::decode(&response_signature)?;
                println!("signature_bytes {:?}", signature_bytes);
                let g1: ark_bn254::g1::G1Affine =
                    ark_bn254::g1::G1Affine::deserialize_uncompressed(&signature_bytes[..])?;

                let mut task_response_buffer = vec![0u8; 12];
                task_response_buffer.extend_from_slice(&hex::decode(&ruleset)?);
                task_response_buffer.extend_from_slice(&stream_event.machineHash.to_vec());

                let mut hasher = Keccak256::new();
                hasher.update(&stream_event.input.clone());
                let payload_keccak = hasher.finalize();

                task_response_buffer.extend_from_slice(&payload_keccak.to_vec());
                task_response_buffer.extend_from_slice(&finish_result);

                let task_response_digest = keccak256(&task_response_buffer);

                bls_agg_service
                    .initialize_new_task(
                        TASK_INDEX,
                        current_block_num as u32,
                        quorum_nums.clone(),
                        quorum_threshold_percentages.clone(),
                        time_to_expiry,
                    )
                    .await?;

                bls_agg_service
                    .process_new_signature(
                        TASK_INDEX,
                        task_response_digest,
                        Signature::new(g1),
                        operator_id.into(),
                    )
                    .await?;

                response_digest_map.insert(
                    B256::from_slice(task_response_digest.as_slice()),
                    outputs_vector.clone(),
                );
            }
            None => {
                return Err(
                    format!("No socket for operator_id {:?}", hex::encode(operator_id)).into(),
                );
            }
        }
    }
    let bls_agg_response = bls_agg_service
        .aggregated_response_receiver
        .lock()
        .await
        .recv()
        .await
        .unwrap()
        .unwrap();
    println!(
        "agg_response_to_non_signer_stakes_and_signature {:?}",
        bls_agg_response
    );
    Ok((bls_agg_response, response_digest_map))
}
fn extract_number_array(values: Vec<serde_json::Value>) -> Vec<u8> {
    let mut byte_vec = Vec::new();

    for value in values {
        match value {
            serde_json::Value::Number(num) => {
                byte_vec.push(num.as_u64().unwrap() as u8);
            }
            _ => {}
        }
    }

    byte_vec
}

fn new_task_issued_handler_l1(
    l1_ws_endpoint: String,
    l1_http_endpoint: String,
    avs_registry_service: AvsRegistryServiceChainCaller<
        AvsRegistryChainReader,
        OperatorInfoServiceInMemory,
    >,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    config_socket: String,
    ruleset: String,
    max_ops: u64,
    current_block_num: u64,
    secret_key: String,
    task_issuer: Address,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    postgres_connect_request: String,
) {
    task::spawn({
        async move {
            let quorum_nums = [0];
            let quorum_threshold_percentages = vec![100_u8];
            let time_to_expiry = Duration::from_secs(10);

            loop {
                let client = pool.get().await.unwrap();
                match client
                    .query_one(
                        "UPDATE issued_tasks 
                        SET status = $1 
                        WHERE id = (
                            SELECT id 
                            FROM issued_tasks 
                            WHERE status = $2 OR status = $3 
                            ORDER BY 
                                CASE 
                                    WHEN status = $2 THEN 1 
                                    WHEN status = $3 THEN 2 
                                    ELSE 3 
                                END, 
                                id DESC
                            LIMIT 1
                        ) 
                        RETURNING *;",
                        &[
                            &task_status::in_progress,
                            &task_status::in_progress,
                            &task_status::waits_for_handling,
                        ],
                    )
                    .await
                {
                    Ok(row) => {
                        let id: i32 = row.get(0);
                        let machine_hash: Vec<u8> = row.get(1);
                        let input: Vec<u8> = row.get(2);
                        let callback: Vec<u8> = row.get(3);

                        let task_issued = TaskIssued {
                            machineHash: B256::from_slice(&machine_hash),
                            input: input.into(),
                            callback: Address::from_slice(&callback),
                        };
                        let ws_connect = alloy_provider::WsConnect::new(l1_ws_endpoint.clone());
                        let ws_provider = alloy_provider::ProviderBuilder::new()
                            .on_ws(ws_connect)
                            .await
                            .unwrap();
            
                        let current_block_number =
                            ws_provider.clone().get_block_number().await.unwrap();
                        match avs_registry_service
                            .clone()
                            .get_operators_avs_state_at_block(
                                current_block_number as u32,
                                &quorum_nums,
                            )
                            .await
                        {
                            Ok(operators) => {
                                let bls_agg_response = handle_task_issued_operator(
                                    operators,
                                    false,
                                    sockets_map.clone(),
                                    config_socket.clone(),
                                    task_issued.clone(),
                                    avs_registry_service.clone(),
                                    time_to_expiry,
                                    ruleset.clone(),
                                    max_ops,
                                    current_block_num,
                                    quorum_nums.to_vec(),
                                    quorum_threshold_percentages.clone(),
                                )
                                .await
                                .unwrap();
                                let secret_key = SecretKey::from_slice(
                                    &hex::decode(secret_key.clone()).unwrap(),
                                )
                                .unwrap();
                                let signer = PrivateKeySigner::from(secret_key);
                                let wallet = EthereumWallet::from(signer);
                                let provider = ProviderBuilder::new()
                                    .with_recommended_fillers()
                                    .wallet(wallet)
                                    .on_http(l1_http_endpoint.parse().unwrap());
                                let contract =
                                    ResponseCallbackContract::new(task_issuer, &provider);
                                let non_signer_stakes_and_signature_response =
                                    agg_response_to_non_signer_stakes_and_signature(
                                        bls_agg_response.0.clone(),
                                    );
                                let outputs: Vec<alloy_primitives::Bytes> = bls_agg_response
                                    .1
                                    .get(&bls_agg_response.0.task_response_digest)
                                    .unwrap()
                                    .iter()
                                    .map(|bytes| bytes.clone().1.into())
                                    .collect();

                                let call_builder = contract.solverCallbackOutputsOnly(
                                    ResponseSol {
                                        ruleSet: Address::parse_checksummed(
                                            format!("0x{}", ruleset.clone()),
                                            None,
                                        )
                                        .unwrap(),
                                        machineHash: task_issued.machineHash,
                                        payloadHash: keccak256(&task_issued.input),
                                        outputMerkle: outputs_merkle::create_proofs(
                                            outputs
                                                .iter()
                                                .map(|element| keccak256(&element.0))
                                                .collect(),
                                            HEIGHT,
                                        )
                                        .unwrap()
                                        .0,
                                    },
                                    quorum_nums.into(),
                                    100,
                                    100,
                                    current_block_num as u32,
                                    non_signer_stakes_and_signature_response.clone().into(),
                                    task_issued.callback,
                                    outputs,
                                );
                                let root_provider = get_provider(l1_http_endpoint.as_str());
                                let service_manager =
                                    IBLSSignatureChecker::new(task_issuer, root_provider);
                                let check_signatures_result = service_manager
                                    .checkSignatures(
                                        bls_agg_response.0.task_response_digest,
                                        alloy_primitives::Bytes::from(quorum_nums),
                                        current_block_num as u32,
                                        non_signer_stakes_and_signature_response,
                                    )
                                    .call()
                                    .await
                                    .unwrap();
                                println!(
                                    "check_signatures_result {:?} {:?} {:?}",
                                    check_signatures_result._0.signedStakeForQuorum,
                                    check_signatures_result._0.totalStakeForQuorum,
                                    check_signatures_result._1
                                );
                                match call_builder.send().await {
                                    Ok(_pending_tx) => {}
                                    Err(err) => {
                                        println!("Transaction wasn't sent successfully: {err}");
                                    }
                                }

                                //Update status after task was handled
                                client
                                    .execute(
                                        "UPDATE issued_tasks SET status = $1 WHERE id = $2;",
                                        &[&task_status::handled, &id],
                                    )
                                    .await
                                    .unwrap();
                            }
                            Err(e) => println!(
                                "no operators found at block {:?}. Error {:?}",
                                current_block_number, e
                            ),
                        }
                    }
                    Err(_) => {
                        println!("waiting for new notifications");
                        let (notification_client, mut connection) =
                            tokio_postgres::connect(&postgres_connect_request, NoTls)
                                .await
                                .unwrap();
                        let (tx, rx) = futures_channel::mpsc::unbounded();
                        let stream = stream::poll_fn(move |cx| connection.poll_message(cx))
                            .map_err(|e| panic!("{}", e));
                        let connection = stream.forward(tx).map(|r| r.unwrap());
                        tokio::spawn(connection);
                        let mut notification_filter = rx.filter_map(|m| match m {
                            AsyncMessage::Notification(n) => futures_util::future::ready(Some(n)),
                            _ => futures_util::future::ready(None),
                        });

                        match notification_client
                            .batch_execute("LISTEN new_task_issued;")
                            .await
                        {
                            Ok(_) => {}
                            Err(_) => {
                            }
                        }
                        notification_filter.next().await;
                    }
                }
            }
        }
    });
}
fn new_task_issued_handler_l2(
    l2_ws_endpoint: String,
    l1_http_endpoint: String,
    l1_coprocessor_address: String,
    l2_coprocessor_address: String,
    avs_registry_service: AvsRegistryServiceChainCaller<
        AvsRegistryChainReader,
        OperatorInfoServiceInMemory,
    >,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    config_socket: String,
    ruleset: String,
    max_ops: u64,
    current_block_num: u64,
    secret_key: String,
    task_issuer: Address,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    postgres_connect_request: String,
    l2Sender: Address,
    sender_data: Vec<u8>,
    eth_value: String,
) {
    task::spawn({
        async move {
            let client = pool.get().await.unwrap();
            let l2_ws_connect = alloy_provider::WsConnect::new(l2_ws_endpoint.clone());
            let l2_ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(l2_ws_connect)
                .await
                .unwrap();
            let l1_http_provider =
                alloy_provider::ProviderBuilder::new().on_http(l1_http_endpoint.parse().unwrap());
            let quorum_nums = [0];
            let quorum_threshold_percentages = vec![100_u8];
            let time_to_expiry = Duration::from_secs(10);

            let (mut notification_client, mut connection) =
                tokio_postgres::connect(&postgres_connect_request, NoTls)
                    .await
                    .unwrap();
            let (tx, rx) = futures_channel::mpsc::unbounded();
            let stream =
                stream::poll_fn(move |cx| connection.poll_message(cx)).map_err(|e| panic!("{}", e));
            let connection = stream.forward(tx).map(|r| r.unwrap());
            tokio::spawn(connection);
            let mut notification_filter = rx.filter_map(|m| match m {
                AsyncMessage::Notification(n) => futures_util::future::ready(Some(n)),
                _ => futures_util::future::ready(None),
            });

            loop {
                match client
                    .query_one(
                        "UPDATE issued_tasks 
                        SET status = $1 
                        WHERE id = (
                            SELECT id 
                            FROM issued_tasks 
                            WHERE status = $2 OR status = $3 
                            ORDER BY 
                                CASE 
                                    WHEN status = $2 THEN 1 
                                    WHEN status = $3 THEN 2 
                                    ELSE 3 
                                END, 
                                id DESC
                            LIMIT 1
                        ) 
                        RETURNING *;",
                        &[
                            &task_status::in_progress,
                            &task_status::in_progress,
                            &task_status::waits_for_handling,
                        ],
                    )
                    .await
                {
                    Ok(row) => {
                        let id: i32 = row.get(0);
                        let machine_hash: Vec<u8> = row.get(1);
                        let input: Vec<u8> = row.get(2);
                        let callback: Vec<u8> = row.get(3);

                        let task_issued = TaskIssued {
                            machineHash: B256::from_slice(&machine_hash),
                            input: input.into(),
                            callback: Address::from_slice(&callback),
                        };

                        let current_block_number =
                            l1_http_provider.clone().get_block_number().await.unwrap();

                        match avs_registry_service
                            .clone()
                            .get_operators_avs_state_at_block(current_block_number as u32, &[0])
                            .await
                        {
                            Ok(operators) => {
                                let bls_agg_response = handle_task_issued_operator(
                                    operators,
                                    false,
                                    sockets_map.clone(),
                                    config_socket.clone(),
                                    task_issued.clone(),
                                    avs_registry_service.clone(),
                                    Duration::from_secs(10),
                                    ruleset.clone(),
                                    max_ops,
                                    current_block_num,
                                    quorum_nums.to_vec(),
                                    quorum_threshold_percentages.clone(),
                                )
                                .await
                                .unwrap();

                                let secret_key_str: String = secret_key.clone();
                                let secret_key = SecretKey::from_slice(
                                    &hex::decode(secret_key.clone()).unwrap(),
                                )
                                .unwrap();

                                let signer = PrivateKeySigner::from(secret_key);
                                let wallet = EthereumWallet::from(signer);
                                let provider = ProviderBuilder::new()
                                    .with_recommended_fillers()
                                    .wallet(wallet)
                                    .on_http(l1_http_endpoint.parse().unwrap());
                                let non_signer_stakes_and_signature_response =
                                    agg_response_to_non_signer_stakes_and_signature(
                                        bls_agg_response.0.clone(),
                                    );
                                let outputs: Vec<alloy_primitives::Bytes> = bls_agg_response
                                    .1
                                    .get(&bls_agg_response.0.task_response_digest)
                                    .unwrap()
                                    .iter()
                                    .map(|bytes| bytes.clone().1.into())
                                    .collect();

                                let keccak_outputs: Vec<B256> =
                                    outputs.iter().map(|o| keccak256(&o.0)).collect();

                                let ruleSet_addr = Address::parse_checksummed(
                                    format!("0x{}", ruleset.clone()),
                                    None,
                                )
                                .unwrap();
                                let resp_rule_set = ruleSet_addr.0.to_vec();

                                let response_hash_fixed = bls_agg_response.0.task_response_digest;
                                let resp_response_hash = response_hash_fixed.0.to_vec();

                                let machine_hash_fixed = task_issued.machineHash;
                                let resp_machine_hash = machine_hash_fixed.0.to_vec();

                                let payload_hash_fixed = keccak256(&task_issued.input);
                                let resp_payload_hash = payload_hash_fixed.0.to_vec();

                                let (output_merkle_fixed, _) =
                                    outputs_merkle::create_proofs(keccak_outputs, HEIGHT).unwrap();
                                let resp_output_merkle = output_merkle_fixed.0.to_vec();

                                let response = ResponseSol {
                                    ruleSet: Address::parse_checksummed(
                                        format!("0x{}", ruleset.clone()),
                                        None,
                                    )
                                    .unwrap(),
                                    machineHash: task_issued.machineHash,
                                    payloadHash: keccak256(&task_issued.input),
                                    outputMerkle: output_merkle_fixed,
                                };

                                let callback_address_bytes = task_issued.callback.0.to_vec();
                                let outputs_db: Vec<Vec<u8>> =
                                    outputs.iter().map(|o| o.0.to_vec()).collect();

                                // finalization table impl.
                                client
                                    .execute(
                                        "INSERT INTO finalization_data (
                                                    resp_responseHash,
                                                    resp_ruleSet,
                                                    resp_machineHash,
                                                    resp_payloadHash,
                                                    resp_outputMerkle,
                                                    callback_address,
                                                    outputs
                                                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                                                ON CONFLICT (resp_responseHash) DO NOTHING",
                                        &[
                                            &resp_response_hash,
                                            &resp_rule_set,
                                            &resp_machine_hash,
                                            &resp_payload_hash,
                                            &resp_output_merkle,
                                            &callback_address_bytes,
                                            &outputs_db,
                                        ],
                                    )
                                    .await
                                    .unwrap();

                                println!(
                                    "Calling send_message_to_l1 with:\n  l1_http_endpoint = {}\n  l1_coprocessor_address = {}\n  secret_key_str = {}\n  quorum_nums = {:?}\n  current_block_num = {}\n  l2Sender = {}\n  eth_value = {}\n",
                                    l1_http_endpoint,
                                    l1_coprocessor_address,
                                    secret_key_str,
                                    quorum_nums,
                                    current_block_num,
                                    l2Sender,
                                    eth_value,
                                );

                                match send_message_to_l1(
                                    l1_http_endpoint.clone(),
                                    Address::parse_checksummed(
                                        l1_coprocessor_address.clone(),
                                        None,
                                    )
                                    .unwrap(),
                                    secret_key_str.clone(),
                                    response,
                                    quorum_nums.into(),
                                    100,
                                    100,
                                    current_block_num as u32,
                                    non_signer_stakes_and_signature_response.clone(),
                                    l2Sender.clone(),
                                    sender_data.clone(),
                                    eth_value.clone(),
                                )
                                .await
                                {
                                    Ok(tx_hash) => {
                                        println!("Message sent to L1 with tx hash: {:?}", tx_hash);
                                        client
                                            .execute(
                                                "UPDATE issued_tasks SET status = $1 WHERE id = $2;",
                                                &[&task_status::sent_to_l1, &id],
                                            )
                                            .await
                                            .unwrap();
                                    }
                                    Err(err) => {
                                        println!("Failed to send L1 transaction: {err}");
                                    }
                                }
                                client
                                    .execute(
                                        "UPDATE issued_tasks SET status = $1 WHERE id = $2;",
                                        &[&task_status::finalized_on_l2, &id],
                                    )
                                    .await
                                    .unwrap();
                            }
                            Err(e) => println!(
                                "No operators found at block {:?}. Error {:?}",
                                current_block_number, e
                            ),
                        }
                    }
                    Err(_) => {
                        println!("Waiting for new L2 tasks...");
                        match notification_client
                            .batch_execute("LISTEN new_task_issued;")
                            .await
                        {
                            Ok(_) => {}
                            Err(_) => {
                                (notification_client, _) =
                                    tokio_postgres::connect(&postgres_connect_request, NoTls)
                                        .await
                                        .unwrap();
                            }
                        }
                        notification_filter.next().await;
                    }
                }
            }
        }
    });
}

fn subscribe_task_issued_l1(
    l1_ws_endpoint: String,
    l1_http_endpoint: String,
    payment_token: Address,
    task_issuer: Address,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    secret_key: String,
    payment_phrase: String,
) {
    task::spawn({
        async move {
            println!("Started TaskIssued subscription");
            let ws_connect = alloy_provider::WsConnect::new(l1_ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();
            let event_filter = Filter::new()
                .address(task_issuer)
                .event("TaskIssued(bytes32,bytes,address)");
            let event: Event<_, _, ICoprocessor::TaskIssued, _> =
                Event::new(ws_provider.clone(), event_filter);

            let subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();
            while let Ok((stream_event, _)) = stream.next().await.unwrap() {
                println!("new TaskIssued {:?}", stream_event);
                let generated_address = generate_eth_address(
                    pool.clone(),
                    stream_event.machineHash,
                    payment_phrase.clone(),
                )
                .await;
                let secret_key =
                    SecretKey::from_slice(&hex::decode(secret_key.clone()).unwrap()).unwrap();
                let signer = PrivateKeySigner::from(secret_key);
                let wallet = EthereumWallet::from(signer);
                let provider = ProviderBuilder::new()
                    .with_recommended_fillers()
                    .wallet(wallet)
                    .on_http(l1_http_endpoint.parse().unwrap());
                let contract = IERC20::new(payment_token, &provider);
                let balance_caller = contract.balanceOf(generated_address);
                match balance_caller.call().await {
                    Ok(balance) => {
                        println!("balanceOf {:?} = {:?}", generated_address, balance);
                    }
                    Err(err) => {
                        println!("Transaction wasn't sent successfully: {err}");
                    }
                }
                let client = pool.get().await.unwrap();
                match client.execute(
                    "INSERT INTO issued_tasks (machineHash, input, callback, status) VALUES ($1, $2, $3, $4::task_status) ",
                    &[
                        &stream_event.machineHash.0.to_vec(),
                        &stream_event.input.to_vec(),
                        &stream_event.callback.to_vec(),
                        &task_status::waits_for_handling
                    ],
                ).await {
                    Ok(_) => {
                    client
                    .batch_execute(
                        "
                        NOTIFY new_task_issued;",
                    )
                    .await.unwrap();
                },
                    Err(_) => {
                    }
                };
            }
        }
    });
}
async fn send_message_to_l1(
    l1_http_endpoint: String,
    l1_coprocessor_address: Address,
    secret_key: String,
    resp: ResponseSol,
    quorum_numbers: Vec<u8>,
    quorum_threshold_percentage: u32,
    threshold_denominator: u8,
    block_number: u32,
    non_signer_stakes_and_signature_response: NonSignerStakesAndSignature,
    l2Sender: Address,
    senderData: Vec<u8>,
    eth_value: String,
) -> Result<TxHash, Box<dyn Error + Send + Sync>> {
    let decoded_secret_key = SecretKey::from_slice(&hex::decode(secret_key)?)
        .map_err(|e| format!("Invalid secret key: {:?}", e))?;
    let signer = PrivateKeySigner::from(decoded_secret_key);
    let wallet = EthereumWallet::from(signer);

    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(l1_http_endpoint.parse().unwrap());

    let l1_coprocessor = L1Coprocessor::new(l1_coprocessor_address, &provider);

    println!(
        "send_message_to_l1 calldata: {:?}",
        l1_coprocessor
            .solverCallbackNoOutputs(
                resp.clone(),
                quorum_numbers.clone().into(),
                quorum_threshold_percentage,
                threshold_denominator,
                block_number,
                non_signer_stakes_and_signature_response.clone().into(),
                l2Sender,
                senderData.clone().into(),
            )
            .calldata()
    );

    let pending_tx = l1_coprocessor
        .solverCallbackNoOutputs(
            resp,
            quorum_numbers.into(),
            quorum_threshold_percentage,
            threshold_denominator,
            block_number,
            non_signer_stakes_and_signature_response.into(),
            l2Sender,
            senderData.into(),
        )
        .value(eth_value.parse().unwrap())
        .send()
        .await?;

    let receipt = pending_tx;
    Ok(*receipt.tx_hash())
}

fn subscribe_task_issued_l2(
    l2_ws_endpoint: String,
    l2_http_endpoint: String,
    payment_token: Address,
    l2_coprocessor_address: String,
    pool: Pool<PostgresConnectionManager<NoTls>>,
    secret_key: String,
    payment_phrase: String,
) {
    task::spawn({
        async move {
            let client = pool.get().await.unwrap();
            println!("Started TaskIssued subscription on L2");

            let ws_connect = alloy_provider::WsConnect::new(l2_ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();

            let addr_parsed = Address::from_str(&l2_coprocessor_address)
                .expect("Invalid L2 coprocessor address string");

            let event_filter = Filter::new()
                .address(addr_parsed)
                .event("TaskIssued(bytes32,bytes,address)");

            let event: Event<_, _, ICoprocessor::TaskIssued, _> =
                Event::new(ws_provider.clone(), event_filter);

            let mut subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();

            while let Some(result) = stream.next().await {
                match result {
                    Ok((stream_event, _)) => {
                        println!("New TaskIssued event on L2: {:?}", stream_event);

                        let generated_address = generate_eth_address(
                            pool.clone(),
                            stream_event.machineHash,
                            payment_phrase.clone(),
                        )
                        .await;

                        let decoded_secret_key =
                            SecretKey::from_slice(&hex::decode(secret_key.clone()).unwrap())
                                .unwrap();
                        let signer = PrivateKeySigner::from(decoded_secret_key);
                        let wallet = EthereumWallet::from(signer);
                        let provider = ProviderBuilder::new()
                            .with_recommended_fillers()
                            .wallet(wallet)
                            .on_http(l2_http_endpoint.parse().unwrap());

                        let contract = IERC20::new(payment_token, &provider);

                        let balance_caller = contract.balanceOf(generated_address);
                        match balance_caller.call().await {
                            Ok(balance) => {
                                println!("Balance of {:?} = {:?}", generated_address, balance);
                            }
                            Err(err) => {
                                println!("Failed to fetch balance: {:?}", err);
                            }
                        }

                        match client
                                        .execute(
                                            "INSERT INTO issued_tasks (machineHash, input, callback, status) VALUES ($1, $2, $3, $4::task_status)",
                                            &[
                                                &stream_event.machineHash.0.to_vec(),
                                                &stream_event.input.0.to_vec(),
                                                &stream_event.callback.0.to_vec(),
                                                &task_status::waits_for_handling,
                                            ],
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            client
                                                .batch_execute(
                                                    "
                                        NOTIFY new_task_issued;
                                        ",
                                                )
                                                .await
                                                .unwrap();
                                            println!("Inserted new task into the database and notified.");
                                        }
                                        Err(err) => {
                                            eprintln!("Failed to insert task into database: {:?}", err);
                                        }
                                    }
                    }
                    Err(err) => {
                        eprintln!("Error in event stream: {:?}", err);
                    }
                }
            }
        }
    });
}

async fn subscribe_task_completed_l2(
    l2_ws_endpoint: String,
    l2_http_endpoint: String,
    l2_coprocessor_address: Address,
    secret_key: String,
    pool: Pool<PostgresConnectionManager<NoTls>>,
) {
    tokio::spawn(async move {
        println!("started TaskCompleted subscription on L2...");

        let ws_connect = alloy_provider::WsConnect::new(l2_ws_endpoint);
        let ws_provider = match alloy_provider::ProviderBuilder::new()
            .on_ws(ws_connect)
            .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("failed to connect to L2 provider: {}", e);
                return;
            }
        };

        let event_filter = Filter::new()
            .address(l2_coprocessor_address)
            .event("TaskCompleted(bytes32)");
        let event: Event<_, _, IL2Coprocessor::TaskCompleted, _> =
            Event::new(ws_provider.clone(), event_filter);

        let subscription = match event.subscribe().await {
            Ok(sub) => sub,
            Err(e) => {
                eprintln!("failed to subscribe to TaskCompleted events: {}", e);
                return;
            }
        };

        let mut stream = subscription.into_stream();

        while let Some(result) = stream.next().await {
            match result {
                Ok((task_completed_event, _log)) => {
                    println!(
                        "new TaskCompleted event on L2: responseHash={:x}",
                        task_completed_event.responseHash
                    );

                    let client = pool.get().await.unwrap();

                    let row = match client.query_one(
                        "SELECT resp_ruleSet, resp_machineHash, resp_payloadHash, resp_outputMerkle, callback_address, outputs
                         FROM finalization_data WHERE resp_responseHash = $1",
                        &[&task_completed_event.responseHash.0.to_vec()],
                    ).await {
                        Ok(r) => r,
                        Err(err) => {
                            eprintln!("Failed to retrieve finalization_data for responseHash: {:?}", err);
                            continue;
                        }
                    };

                    let resp_rule_set: Vec<u8> = row.get(0);
                    let resp_machine_hash: Vec<u8> = row.get(1);
                    let resp_payload_hash: Vec<u8> = row.get(2);
                    let resp_output_merkle: Vec<u8> = row.get(3);
                    let callback_address_bytes: Vec<u8> = row.get(4);
                    let outputs_db: Vec<Vec<u8>> = row.get(5);

                    let rule_set_addr = Address::from_slice(&resp_rule_set);
                    let machine_hash_fixed = B256::from_slice(&resp_machine_hash);
                    let payload_hash_fixed = B256::from_slice(&resp_payload_hash);
                    let output_merkle_fixed = B256::from_slice(&resp_output_merkle);
                    let callback_addr = Address::from_slice(&callback_address_bytes);

                    let resp = ResponseSol {
                        ruleSet: rule_set_addr,
                        machineHash: machine_hash_fixed,
                        payloadHash: payload_hash_fixed,
                        outputMerkle: output_merkle_fixed,
                    };

                    if let Err(err) = finalize_on_l2(
                        &l2_http_endpoint,
                        l2_coprocessor_address,
                        &secret_key,
                        resp,
                        outputs_db,
                        callback_addr,
                    )
                    .await
                    {
                        eprintln!("error calling finalize_on_l2: {:?}", err);
                    } else {
                        println!("successfully finalized on L2!");
                    }
                }
                Err(err) => {
                    eprintln!("Error reading TaskCompleted events: {:?}", err);
                }
            }
        }
    });
}
async fn finalize_on_l2(
    l2_http_endpoint: &str,
    l2_coprocessor_address: Address,
    secret_key: &str,
    resp: ResponseSol,
    outputs: Vec<Vec<u8>>,
    callback_address: Address,
) -> Result<(), Box<dyn Error>> {
    let outputs_for_sol: Vec<alloy_primitives::Bytes> =
        outputs.into_iter().map(|o| o.into()).collect();

    let secret_key = alloy::signers::k256::SecretKey::from_slice(&hex::decode(secret_key)?)?;
    let signer = alloy_signer_local::PrivateKeySigner::from(secret_key);
    let wallet = alloy_network::EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .with_recommended_fillers()
        .wallet(wallet)
        .on_http(l2_http_endpoint.parse().unwrap());

    let l2_coprocessor = L2Coprocessor::new(l2_coprocessor_address, &provider);

    let call_builder =
        l2_coprocessor.callbackWithOutputs(resp.clone(), outputs_for_sol.clone(), callback_address);

    println!(
        "callbackWithOutputs transaction on L2 with:\n  resp = {:?}\n  outputs = {:?}\n  callbackAddress = {:?}\n calldata = {:?}",
        resp,
        outputs_for_sol,
        callback_address,
        call_builder.calldata()
    );

    match call_builder.send().await {
        Ok(pending_tx) => {
            println!(
                "L2 callbackWithOutputs transaction sent! TxHash: {:?}",
                pending_tx.tx_hash()
            );
        }
        Err(err) => {
            eprintln!(
                "Failed to send callbackWithOutputs transaction on L2: {:?}",
                err
            );
        }
    }

    Ok(())
}

fn subscribe_operator_socket_update(
    arc_ws_endpoint: Arc<String>,
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    registry_coordinator_address: Address,
    current_last_block: Arc<Mutex<u64>>,
) {
    task::spawn({
        println!("Started OperatorSocketUpdate subscription");

        let ws_endpoint = Arc::clone(&arc_ws_endpoint);
        let sockets_map = Arc::clone(&sockets_map);

        async move {
            let ws_connect = alloy_provider::WsConnect::new((*ws_endpoint).clone());
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();
            let event_filter = Filter::new()
                .address(registry_coordinator_address)
                .event("OperatorSocketUpdate(bytes32,string)")
                .from_block(*current_last_block.lock().await);

            let event: Event<_, _, ISocketUpdater::OperatorSocketUpdate, _> =
                Event::new(ws_provider, event_filter);

            let subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();
            while let Ok((stream_event, _)) = stream.next().await.unwrap() {
                sockets_map.lock().await.insert(
                    stream_event.operatorId.as_slice().to_vec(),
                    stream_event.socket,
                );
            }
        }
    });
}

async fn generate_eth_address(
    pool: Pool<PostgresConnectionManager<NoTls>>,
    machine_hash: FixedBytes<32>,
    payment_phrase: String,
) -> Address {
    let client = pool.get().await.unwrap();
    let _ = client
        .execute(
            "INSERT INTO machine_hashes (machine_hash) VALUES ($1)",
            &[&machine_hash.to_vec()],
        )
        .await;
    let address_index = client
        .query_one(
            "SELECT id FROM machine_hashes WHERE machine_hash = $1 ",
            &[&machine_hash.to_vec()],
        )
        .await
        .unwrap();

    let index: i32 = address_index.get(0);

    let builder = MnemonicBuilder::<coins_bip39::wordlist::english::English>::default()
        .index(index as u32)
        .unwrap()
        .phrase(payment_phrase)
        .build()
        .unwrap();
    builder.address()
}
impl Into<NonSignerStakesAndSignatureSol> for NonSignerStakesAndSignature {
    fn into(self) -> NonSignerStakesAndSignatureSol {
        let apk_g2 = G2PointSol {
            X: self.apkG2.X,
            Y: self.apkG2.Y,
        };
        let sigma = G1PointSol {
            X: self.sigma.X,
            Y: self.sigma.Y,
        };
        NonSignerStakesAndSignatureSol {
            nonSignerPubkeys: self
                .nonSignerPubkeys
                .iter()
                .map(|g1_point| G1PointSol {
                    X: g1_point.X,
                    Y: g1_point.Y,
                })
                .collect(),
            quorumApks: self
                .quorumApks
                .iter()
                .map(|g1_point| G1PointSol {
                    X: g1_point.X,
                    Y: g1_point.Y,
                })
                .collect(),
            apkG2: apk_g2,
            sigma,
            nonSignerQuorumBitmapIndices: self.nonSignerQuorumBitmapIndices,
            quorumApkIndices: self.quorumApkIndices,
            totalStakeIndices: self.totalStakeIndices,
            nonSignerStakeIndices: self.nonSignerStakeIndices,
        }
    }
}

fn check_preimage_hash(hash: &Vec<u8>, data: &Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    if &result.to_vec() == hash {
        return Ok(());
    } else {
        return Err(Box::<dyn std::error::Error>::from(
            "keccak256 of the data and the hash don't match",
        ));
    }
}

fn agg_response_to_non_signer_stakes_and_signature(
    agg_response: BlsAggregationServiceResponse,
) -> NonSignerStakesAndSignature {
    let non_signer_pubkeys: Vec<G1Point> = agg_response
        .non_signers_pub_keys_g1
        .iter()
        .map(|point| convert_to_bls_checker_g1_point(point.g1()).unwrap())
        .collect();
    let quorum_apks = agg_response
        .quorum_apks_g1
        .iter()
        .map(|point| convert_to_bls_checker_g1_point(point.g1()).unwrap())
        .collect();

    NonSignerStakesAndSignature {
        nonSignerPubkeys: non_signer_pubkeys,
        quorumApks: quorum_apks,
        apkG2: convert_to_bls_checker_g2_point(agg_response.signers_apk_g2.g2()).unwrap(),
        sigma: convert_to_bls_checker_g1_point(agg_response.signers_agg_sig_g1.g1_point().g1())
            .unwrap(),
        nonSignerQuorumBitmapIndices: agg_response.non_signer_quorum_bitmap_indices,
        quorumApkIndices: agg_response.quorum_apk_indices,
        totalStakeIndices: agg_response.total_stake_indices,
        nonSignerStakeIndices: agg_response.non_signer_stake_indices,
    }
}
sol!(
   interface ICoprocessor {
        #[derive(Debug)]
        event TaskIssued(bytes32 machineHash, bytes input, address callback);
   }
);

sol! {
    interface IL2Coprocessor {
        #[derive(Debug)]
        event TaskCompleted(bytes32 responseHash);
    }
}

sol!(
    #[sol(rpc)]
    contract IERC20 {
        constructor(address) {}

        #[derive(Debug)]
        function balanceOf(address account) external view returns (uint256);
    }
);

sol!(
    interface ISocketUpdater {
        // EVENTS
        #[derive(Debug)]
        event OperatorSocketUpdate(bytes32 indexed operatorId, string socket);
    }
);
sol!(
    interface ICoprocessorL2Sender {
        function sendMessage(bytes32 respHash, bytes calldata senderData) external payable;
    }
);

sol! {
    #[derive(Debug, Default)]
    struct ResponseSol {
        address ruleSet;
        bytes32 machineHash;
        bytes32 payloadHash;
        bytes32 outputMerkle;
    }
    #[derive(Debug)]
        struct G1PointSol {
            uint256 X;
            uint256 Y;
        }
        #[derive(Debug)]
        struct G2PointSol {
            uint256[2] X;
            uint256[2] Y;
        }
    #[derive(Debug)]
    struct NonSignerStakesAndSignatureSol {
        uint32[] nonSignerQuorumBitmapIndices;
        G1PointSol[] nonSignerPubkeys;
        G1PointSol[] quorumApks;
        G2PointSol apkG2;
        G1PointSol sigma;
        uint32[] quorumApkIndices;
        uint32[] totalStakeIndices;
        uint32[][] nonSignerStakeIndices;
     }
    #[sol(rpc)]
    contract ResponseCallbackContract {
        constructor(address) {}

        #[derive(Debug)]
        function solverCallbackOutputsOnly(
            ResponseSol calldata resp,
            bytes calldata quorumNumbers,
            uint32 quorumThresholdPercentage,
            uint8 thresholdDenominator,
            uint32 blockNumber,
            NonSignerStakesAndSignatureSol memory nonSignerStakesAndSignature,
            address callback_address,
            bytes[] calldata outputs
        );
    }
    #[sol(rpc)]
    contract L1Coprocessor {
        //constructor(address _crossDomainMessenger, IRegistryCoordinator _registryCoordinator) {}

        function setL2Coprocessor(address _l2Coprocessor) external;

        #[derive(Debug)]
        function solverCallbackNoOutputs(
            ResponseSol calldata resp,
            bytes calldata quorumNumbers,
            uint32 quorumThresholdPercentage,
            uint8 thresholdDenominator,
            uint32 blockNumber,
            NonSignerStakesAndSignatureSol memory nonSignerStakesAndSignature,
            address l2Sender,
            bytes calldata senderData
        ) external;

    }

    //l2 contract interface
    #[sol(rpc)]
    contract L2Coprocessor {
        function callbackWithOutputs(
            ResponseSol calldata resp,
            bytes[] calldata outputs,
            address callbackAddress
        );
    }
}
