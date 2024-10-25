use alloy::signers::k256::SecretKey;
use alloy_contract::Event;
use alloy_primitives::{keccak256, Address, FixedBytes, Keccak256, B256};
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types_eth::Filter;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::sol;
use ark_serialize::CanonicalDeserialize;
use async_std::{sync::Mutex, task, task::JoinHandle};
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
use futures_util::StreamExt;
use hex::FromHex;
use hyper::{
    service::{make_service_fn, service_fn},
    Body, Client, Request, Response, Server, StatusCode,
};
use serde::Deserialize;
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use ICoprocessor::TaskIssued;
mod outputs_merkle;
use alloy_network::EthereumWallet;
const HEIGHT: usize = 63;
const TASK_INDEX: u32 = 1;

#[derive(Deserialize)]
struct Config {
    http_endpoint: String,
    ws_endpoint: String,
    registry_coordinator_address: Address,
    operator_state_retriever_address: Address,
    current_first_block: u64,
    task_issuer: Address,
    ruleset: String,
    socket: String,
    secret_key: String,
}
#[async_std::main]
async fn main() {
    let config_string = std::fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&config_string).unwrap();

    println!("Starting solver..");
    let arc_ws_endpoint = Arc::new(config.ws_endpoint.clone());

    let tracing_logger =
        TracingLogger::new_text_logger(false, String::from(""), LogLevel::Debug, false);
    let avs_registry_reader = AvsRegistryChainReader::new(
        tracing_logger.clone(),
        config.registry_coordinator_address,
        config.operator_state_retriever_address,
        config.http_endpoint.clone(),
    )
    .await
    .unwrap();

    let operators_info = OperatorInfoServiceInMemory::new(
        tracing_logger.clone(),
        avs_registry_reader.clone(),
        config.ws_endpoint.clone(),
    )
    .await;
    let avs_registry_service =
        AvsRegistryServiceChainCaller::new(avs_registry_reader, operators_info.clone());

    let cancellation_token = CancellationToken::new();
    let operators_info_clone = Arc::new(operators_info.clone());
    let token_clone = cancellation_token.clone();
    let provider =
        alloy_provider::ProviderBuilder::new().on_http(config.http_endpoint.parse().unwrap());
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
    let sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let current_last_block = Arc::new(Mutex::new(config.current_first_block));
    let querying_thread = query_operator_socket_update(
        config.ws_endpoint.clone(),
        sockets_map.clone(),
        config.current_first_block,
        current_last_block.clone(),
        config.registry_coordinator_address,
    );

    let ruleset = config.ruleset.clone();
    let addr: SocketAddr = ([0, 0, 0, 0], 3034).into();
    let service = make_service_fn(|_| {
        let avs_registry_service = avs_registry_service.clone();
        let ws_endpoint = config.ws_endpoint.clone();
        let config_socket = config.socket.clone();

        let sockets_map = sockets_map.clone();
        let ruleset = ruleset.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let avs_registry_service = avs_registry_service.clone();
                let ws_endpoint = ws_endpoint.clone();
                let config_socket = config_socket.clone();

                let sockets_map = sockets_map.clone();
                let ruleset = ruleset.clone();

                async move {
                    let path = req.uri().path().to_owned();
                    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

                    match (req.method().clone(), &segments as &[&str]) {
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
                                            .expect("valid checksum"),
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
                        (hyper::Method::POST, ["ensure", cid_str, machine_hash, size_str]) => {
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
    querying_thread.await;
    println!("Finished OperatorSocketUpdate querying");
    subscribe_task_issued(
        sockets_map.clone(),
        operators_info,
        config.secret_key,
        config.ws_endpoint.clone(),
        config.http_endpoint.clone(),
        config.socket.clone(),
        config.task_issuer,
        config.ruleset,
        current_block_num,
        avs_registry_service.clone(),
    );
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
                    .uri(format!("{}/classic/{:x}", socket, stream_event.machineHash))
                    .body(Body::from(stream_event.input.to_vec()))
                    .unwrap();
                println!("{}/classic/{:x}", socket, stream_event.machineHash);
                let client = Client::new();
                let response = client.request(request).await.unwrap();
                let response_json = serde_json::from_slice::<serde_json::Value>(
                    &hyper::body::to_bytes(response)
                        .await
                        .expect(
                            format!(
                                "No respose for {}/classic/{:x}",
                                socket, stream_event.machineHash,
                            )
                            .as_str(),
                        )
                        .to_vec(),
                )
                .unwrap();

                let response_signature: String = match response_json.get("signature") {
                    Some(serde_json::Value::String(sign)) => sign.to_string(),
                    _ => {
                        panic!("No signature found in request response");
                    }
                };

                let finish_callback: Vec<serde_json::Value> =
                    match response_json.get("finish_callback") {
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
                            panic!("No finish_callback found in request response");
                        }
                    };
                let finish_result = extract_number_array(finish_callback);
                let outputs_vector: Vec<(u16, Vec<u8>)> =
                    match response_json.get("outputs_callback_vector") {
                        Some(outputs_callback) => {
                            serde_json::from_value(outputs_callback.clone()).unwrap()
                        }
                        _ => {
                            panic!("No outputs_callback_vector found in request response");
                        }
                    };
                if generate_proofs {
                    let mut keccak_outputs = Vec::new();

                    for output in outputs_vector.clone() {
                        let mut hasher = Keccak256::new();
                        hasher.update(output.1.clone());
                        keccak_outputs.push(hasher.finalize());
                    }

                    let proofs = outputs_merkle::create_proofs(keccak_outputs, HEIGHT).unwrap();

                    if proofs.0.to_vec() != finish_result {
                        return Err(format!("Outputs weren't proven successfully").into());
                    }
                }

                let signature_bytes = hex::decode(&response_signature).unwrap();
                println!("signature_bytes {:?}", signature_bytes);
                let g1: ark_bn254::g1::G1Affine =
                    ark_bn254::g1::G1Affine::deserialize_uncompressed(&signature_bytes[..])
                        .unwrap();

                let mut task_response_buffer = vec![0u8; 12];
                task_response_buffer.extend_from_slice(&hex::decode(&ruleset).unwrap());
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
                    .await
                    .unwrap();

                bls_agg_service
                    .process_new_signature(
                        TASK_INDEX,
                        task_response_digest,
                        Signature::new(g1),
                        operator_id.into(),
                    )
                    .await
                    .unwrap();

                response_digest_map.insert(
                    B256::from_slice(task_response_digest.as_slice()),
                    outputs_vector.clone(),
                );
            }
            None => {
                eprint!("No socket for operator_id {:?}", hex::encode(operator_id));
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
fn subscribe_task_issued(
    sockets_map: Arc<Mutex<HashMap<Vec<u8>, String>>>,
    operators_info: OperatorInfoServiceInMemory,
    secret_key: String,
    ws_endpoint: String,
    http_endpoint: String,
    config_socket: String,
    task_issuer: Address,
    ruleset: String,
    current_block_num: u64,
    avs_registry_service: AvsRegistryServiceChainCaller<
        AvsRegistryChainReader,
        OperatorInfoServiceInMemory,
    >,
) {
    task::spawn({
        let sockets_map = Arc::clone(&sockets_map);
        async move {
            operators_info.past_querying_finished.notified().await;
            println!("Started TaskIssued subscription");
            let ws_connect = alloy_provider::WsConnect::new(ws_endpoint);
            let ws_provider = alloy_provider::ProviderBuilder::new()
                .on_ws(ws_connect)
                .await
                .unwrap();
            let event_filter = Filter::new().address(task_issuer);
            let event: Event<_, _, ICoprocessor::TaskIssued, _> =
                Event::new(ws_provider.clone(), event_filter);

            let subscription = event.subscribe().await.unwrap();
            let mut stream = subscription.into_stream();
            let quorum_nums = [0];
            let quorum_threshold_percentages = vec![100_u8];
            let time_to_expiry = Duration::from_secs(10);
            while let Ok((stream_event, _)) = stream.next().await.unwrap() {
                println!("new TaskIssued {:?}", stream_event);
                let current_block_number = ws_provider.clone().get_block_number().await.unwrap();
                match avs_registry_service
                    .clone()
                    .get_operators_avs_state_at_block(current_block_number as u32, &quorum_nums)
                    .await
                {
                    Ok(operators) => {
                        let bls_agg_response = handle_task_issued_operator(
                            operators,
                            false,
                            sockets_map.clone(),
                            config_socket.clone(),
                            stream_event.clone(),
                            avs_registry_service.clone(),
                            time_to_expiry,
                            ruleset.clone(),
                            current_block_num,
                            quorum_nums.to_vec(),
                            quorum_threshold_percentages.clone(),
                        )
                        .await
                        .unwrap();

                        let secret_key =
                            SecretKey::from_slice(&hex::decode(secret_key.clone()).unwrap())
                                .unwrap();
                        let signer = PrivateKeySigner::from(secret_key);
                        let wallet = EthereumWallet::from(signer);
                        let provider = ProviderBuilder::new()
                            .wallet(wallet)
                            .on_http(http_endpoint.parse().unwrap());
                        let contract = ResponseCallbackContract::new(task_issuer, &provider);

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
                        let mut hasher = Keccak256::new();
                        hasher.update(&stream_event.input);
                        let payload_hash = hasher.finalize();
                        let call_builder = contract.solverCallbackOutputsOnly(
                            ResponseSol {
                                ruleSet: Address::parse_checksummed(format!("0x{ruleset}"), None)
                                    .unwrap(),
                                machineHash: stream_event.machineHash,
                                payloadHash: payload_hash,
                                outputMerkle: outputs_merkle::create_proofs(
                                    outputs
                                        .iter()
                                        .map(|element| {
                                            let mut hasher = Keccak256::new();
                                            hasher.update(&element.0);
                                            hasher.finalize()
                                        })
                                        .collect(),
                                    HEIGHT,
                                )
                                .unwrap()
                                .0,
                            },
                            quorum_nums.into(),
                            100, // XXX ?
                            100,
                            current_block_num as u32,
                            non_signer_stakes_and_signature_response.clone().into(),
                            stream_event.callback,
                            outputs,
                        );

                        let root_provider = get_provider(http_endpoint.as_str());

                        let service_manager = IBLSSignatureChecker::new(task_issuer, root_provider);
                        let check_signatures_result = service_manager
                            .checkSignatures(
                                bls_agg_response.0.task_response_digest,
                                alloy_primitives::Bytes::from(quorum_nums.clone()),
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
                        let pending_tx = call_builder.send().await.unwrap();
                    }
                    Err(e) => println!(
                        "no operators found at block {:?}. Error {:?}",
                        current_block_number, e
                    ),
                }
            }
        }
    });
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

sol!(
    interface ISocketUpdater {
        // EVENTS
        #[derive(Debug)]
        event OperatorSocketUpdate(bytes32 indexed operatorId, string socket);
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
}
