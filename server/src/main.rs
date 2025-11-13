use pqcrypto_sphincsplus::sphincssha2128fsimple::{
    keypair, detached_sign, verify_detached_signature,
    PublicKey, SecretKey, DetachedSignature
};
use std::collections::HashSet;
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait };
use pqcrypto_traits::sign::DetachedSignature as DetachedSignatureTrait;
use sled;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_keccak::{Hasher, Keccak};
use sha2::{Sha256, Digest};
use hex;
use std::str::FromStr;
use eyre::Result;
use futures::future::join_all;
use tokio;
use warp::Filter;
use serde_json::json;
use sha3::{Keccak256};
use eyre::anyhow;
use std::thread;
use serde_json::Value;
use std::cmp::max; 
use nng::{Socket, Protocol};
use std::sync::{Arc, Mutex};
use reqwest::Client;
use sled::IVec;
use rand::Rng;
use nng::options::protocol::pubsub::Subscribe;
use nng::options::Options;
use std::error::Error;
use std::collections::HashMap;
use std::env;
use std::time::{Instant, Duration};
use std::io::{self, BufRead};
use std::process;
use warp::filters::addr::remote;
use tokio::time::{sleep, Duration as tDuration};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use dashmap::DashMap;
use uuid::Uuid;
use tokio::sync::{Mutex as tMutex};
use std::io::{BufReader as iBufReader, Write as iWrite};
use std::net::{TcpListener as nTcpListener, TcpStream as nTcpStream};
use blake3;
use colored::Colorize;
use regex::Regex;

mod config;
mod constants;
use constants::*;
mod functions;
use functions::*;
use functions::{MinerInfo, Block};
mod crypto;
use crypto::*;
mod network;
use network::*;

use randomx_rs::{RandomXCache, RandomXVM, RandomXFlag};
use hex::decode;
use hex::encode;
use std::convert::TryInto;
use once_cell::sync::Lazy;
use tokio::net::tcp::OwnedWriteHalf;

pub fn start_local_hash_server() -> std::io::Result<()> {
    let listener = nTcpListener::bind("127.0.0.1:22666")?;
	print_log_message(format!("rx/0 started"), 1);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_hash_connection(stream);
            }
            Err(e) => {
                eprintln!("local conn error: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_hash_connection(mut stream: nTcpStream) {
    let peer = stream.peer_addr().unwrap_or_else(|_| "unknown".parse().unwrap());

    let mut reader = iBufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();

    if reader.read_line(&mut request_line).is_ok() {
        if let Ok(json_req) = serde_json::from_str::<Value>(&request_line) {
            let blob = json_req["blob"].as_str().unwrap_or("");
            let nonce = json_req["nonce"].as_str().unwrap_or("");
			let seed = json_req["seed"].as_str().unwrap_or("");
			let response;
			if seed == "" {
				response = match compute_randomx_hash(blob, nonce) {
					Ok(hash) => json!({
						"status": "ok",
						"hash": hash,
					}),
					Err(e) => json!({
						"status": "error",
						"message": e.to_string(),
					}),
				};
			} else {
				response = match dynamic_compute_randomx_hash(blob, nonce, seed) {
					Ok(hash) => json!({
						"status": "ok",
						"hash": hash,
					}),
					Err(e) => json!({
						"status": "error",
						"message": e.to_string(),
					}),
				};
			}

            let response_text = serde_json::to_string(&response).unwrap() + "\n";
            let _ = stream.write_all(response_text.as_bytes());
        } else {
            let _ = stream.write_all(b"{\"status\":\"error\",\"message\":\"invalid json\"}\n");
        }
    }
}

fn print_banner() {
    use figlet_rs::FIGfont;

    let standard_font = FIGfont::standard().unwrap();
    let figure = standard_font.convert("XPARASITE - 1.4").unwrap();
    println!("{}", figure.to_string().purple().bold());
}


fn is_valid_address(addr: &str) -> bool {
    let re = Regex::new(r"^xP[0-9a-fA-F]{62}$").unwrap();
    re.is_match(addr)
}

#[tokio::main]
async fn main() -> sled::Result<()> {	
	#[cfg(windows)]
    colored::control::set_virtual_terminal(true).unwrap();

	let args: Vec<String> = env::args().collect();
	let help_mode = args.iter().any(|arg| arg == "--help") as u8;
	let rng_mode = args.iter().any(|arg| arg == "--rng") as u8;
	
	if help_mode == 1 {
		println!("Options:");
		println!("  --address addr   Set up your node address.");
		println!("  --help           Display this help menu.");
		println!();
		println!("Example:");
		println!("  xparad --address xPbcd2f76102e4aa3eeb066ef41b5a60a150683740a8a284a86a66f4459cfa73");
		process::exit(0);
	}
	
	print_banner();
	
    let mut node_address = "000000".to_string();
    if let Some(pos) = args.iter().position(|arg| arg == "--address") {
        if let Some(addr) = args.get(pos + 1) {
            node_address = addr.clone();
        } else {
            eprintln!("Error: --address option requires a valid xPARA address.");
            process::exit(1);
        }
    }
    while !is_valid_address(&node_address) {
        println!("Please enter a valid xPARA address:");
        print!("> ");
        io::stdout().flush().unwrap();

        node_address.clear();
        io::stdin().read_line(&mut node_address).unwrap();
        node_address = node_address.trim().to_string();
    }
	
	config::load();
	if rng_mode == 1 {
		config::update_rng(1);
	} else {
		config::update_rng(0);
	}
	config::update_node_address(node_address);	
	let utxodb = config::utxodb();
	let mempooldb = config::mempooldb();
	for key in mempooldb.iter().keys() {
        let k = key?;
        mempooldb.remove(k)?;
    }
    mempooldb.flush()?;
    println!("Mempool started successfully.");
	
	let response = reqwest::get("https://xpara.site/ts.php").await;
    if let Ok(resp) = response {
        if let Ok(text) = resp.text().await {
            if let Ok(remote_ts) = text.trim().parse::<u64>() {
                let local_ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let mut diff = remote_ts as i64 - local_ts as i64;
				if diff > 0 {
					diff = diff - 1;
				}
				config::update_ts_diff(diff);
            }
        }
    }
	
	set_latest_block_info();
	preload_block_history();
	print_log_message(format!("chain started. height: {}, hash: {}", config::actual_height(), config::actual_hash()), 1);
	print_log_message(format!("node started. address: {}", config::node_address()), 1);
	
	thread::spawn(|| {
		if let Err(e) = start_local_hash_server() {
			eprintln!("local server error: {}", e);
		}
	});

	sleep(tDuration::from_millis(1300));

	if let Ok(mut stream) = nTcpStream::connect("127.0.0.1:16789") {
		let request = json!({
			"blob": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			"nonce": "11111111"
		});
		if let Ok(req_str) = serde_json::to_string(&request) {
			let _ = stream.write_all(req_str.as_bytes());
			let _ = stream.write_all(b"\n");
			let mut reader = iBufReader::new(stream);
			let mut response = String::new();
			if let Ok(_) = reader.read_line(&mut response) {
				if let Ok(json_resp) = serde_json::from_str::<serde_json::Value>(&response) {
					if json_resp["status"] == "ok" {
						if let Some(hash_str) = json_resp["hash"].as_str() {
							print_log_message(format!("rx/0 started: {}", hash_str), 4);
						}
					}
				}
			}
		}
	}

	/*println!("");
	println!("Available commands:");
	println!("  help        - Show this help message");
	println!("  version     - Show server version");
	println!("  miners      - Show active miners in the last 600 seconds");
	println!("  lastblock   - Show details of the most recently mined block");
	println!("  setloglevel - Set log level (1 to 4)");
	println!("");*/
	
	// i/o thread
	/*thread::spawn(move || {
		loop {
			let mut input = String::new();
			io::stdin().read_line(&mut input).unwrap();
			let parts: Vec<&str> = input.trim().split_whitespace().collect();

			if parts.is_empty() {
				continue;
			}

			match parts[0] {
				"version" => {
					println!("XPARASITE v1");
				}
				"help" => {
					println!("Available commands:");
					println!("  help        - Show this help message");
					println!("  version     - Show server version");
					println!("  lastblock   - Show details of the most recently mined block");
					println!("  setloglevel - Set log level (1 to 4)");
				}
				"lastblock" => {
					println!("Last mined block:");
					let (actual_height, actual_hash, actual_ts) = get_latest_block_info();
					println!("Height: {}, Hash: {}, Timestamp: {}", actual_height, actual_hash, actual_ts);
				}
				"setloglevel" => {
					if parts.len() < 2 {
						println!("Please specify a log level (1 to 4).");
						continue;
					}
					match parts[1].parse::<u64>() {
						Ok(level) if level >= 1 && level <= 4 => {
							config::update_log_level(level);
							println!("Log level set to {}", level);
						}
						_ => {
							println!("Wrong log level value");
						}
					}
				}
				_ => {
					println!("Unknown command. Type 'help' to see available commands.");
				}
			}
		}
	});*/
	
	let servers = vec![
		"xpara.site".to_string(),
		"node1.xpara.site".to_string(),
		"node2.xpara.site".to_string(),
	];
	
	print_log_message(format!("syncing blocks..."), 1);
	config::update_full_sync(1);
	for server in &servers {
		print_log_message(format!("syncing from: {}", server), 4);
		let _ = tokio::spawn(full_sync_blocks(server.clone())).await.unwrap();
	}
	config::update_full_sync(0);
	print_log_message("sync ended...".to_string(), 1);

	start_nng_server(servers.clone());

	for server in &servers {
		let server = server.clone();
		tokio::spawn(async {
			let _ = connect_to_nng_server(server);
		});
	}
	for (i, server) in servers.iter().enumerate() {
		let server = server.clone();
		tokio::spawn(async {
			sleep(tDuration::from_millis(1300));
			let _ = connect_to_http_server(server);
		});
	}


	let rpc_route = warp::path("rpc")
		.and(warp::post())
		.and(remote())
		.and(warp::body::json())
		.map(|addr: Option<std::net::SocketAddr>, data: serde_json::Value| {
			
			if let Some(addr) = addr {
				print_log_message(format!("request from: {}", addr.ip()), 4);
			} else {
				print_log_message("request from: unknown".to_string(), 4);
			}
			
			//print_log_message(format!("recv: {}", data), 4);
			
			let id = data["id"].as_str().unwrap_or("unknown");
			let method = data["method"].as_str().unwrap_or("");
			
			let response = match method {
				"xp_getBlocks" => {
					let block_number = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.and_then(|s| s.parse::<u64>().ok())
						.unwrap_or(1);
					let blocks = get_next_blocks(block_number);
					json!({"jsonrpc": "2.0", "id": id, "result": blocks})
				},
				"xp_getBlockByHeight" => {
					let block_number = data["params"]
						.get(0)
						.and_then(|v| v.as_str())
						.and_then(|s| s.parse::<u64>().ok())
						.unwrap_or(1);
					let block_json = get_block_as_json(block_number);
					json!({ "jsonrpc": "2.0", "id": id, "result": block_json })
				},
				"xp_blockNumber" => {
					let (actual_height, _actual_hash, _) = get_latest_block_info();
					let block_number = format!("0x{:x}", actual_height);
					json!({"jsonrpc": "2.0", "id": id, "result": block_number})
				},
				"xp_getMempool" => {
					match get_mempool_records() {
						Ok(mempool) => {
							json!({"jsonrpc": "2.0", "id": id, "result": mempool})
						},
						Err(e) => {
							json!({
								"jsonrpc": "2.0",
								"id": id,
								"error": {
									"code": -32000,
									"message": format!("Error getting mempool records: {}", e)
								}
							})
						}
					}
				},
				"xp_sendRawTransaction" => {
					let mut txhash = String::from("");
					if let Some(params) = data["params"].as_array() {
						if let Some(raw_tx) = params.get(0) {
							if let Some(raw_tx_str) = raw_tx.as_str() {
								if let Ok(tx_bytes) = hex::decode(&raw_tx_str) {
									match bincode::deserialize::<RawTransaction>(&tx_bytes) {
										Ok(raw_tx) => {
											let rtx = RawTransaction {
												inputcount: raw_tx.inputcount,
												inputs: raw_tx.inputs.clone(),
												outputcount: raw_tx.outputcount,
												outputs: raw_tx.outputs.clone(),
												fee: raw_tx.fee,
												sigpub: raw_tx.sigpub.clone(),
												signature: "".to_string(),
											};
											
											let mut total_inputs_amount = 0u64;
											let total_outputs_amount: u64 = raw_tx.outputs.iter().map(|(_, amount)| amount).sum();
											let mut required_amount = total_outputs_amount + raw_tx.fee;
											
											let tx_binary = bincode::serialize(&rtx)
												.expect("Failed to serialize transaction");
											let tx_hash = blake3::hash(&tx_binary);
											
											let bytes_decoded_signature = hex::decode(&raw_tx.signature).expect("Error decoding signature");
											let decoded_signature = <pqcrypto_sphincsplus::sphincssha2128fsimple::DetachedSignature as DetachedSignatureTrait>::from_bytes(&bytes_decoded_signature)
												.expect("Error in signature reconstruction");
											
											let pk_bytes = hex::decode(&raw_tx.sigpub).expect("Invalid pubkey");
											let pk = PublicKey::from_bytes(&pk_bytes).expect("Invalid pubkey format");
											
											let address_hash = blake3::hash(pk.as_bytes());
											let mut sender_address = hex::encode(address_hash.as_bytes());
											sender_address.replace_range(0..2, "xP");

											match verify_detached_signature(&decoded_signature, tx_hash.as_bytes(), &pk) {
												Ok(_) => print_log_message(format!("valid tx received"), 2),
												Err(e) => {
													print_log_message(format!("invalid tx received"), 2);
													//print_log_message(format!("Details: {}", e), 3);
													required_amount = 9999999999999999;
												}
											}
											
											for input in &raw_tx.inputs {
												let key = format!("{}:{}", input.txid, input.vout);
												if let Ok(Some(utxo_bytes)) = utxodb.get(&key) {
													let utxo_value: serde_json::Value = serde_json::from_slice(&utxo_bytes).expect("Failed to parse UTXO JSON");
													let amount = utxo_value["amount"].as_u64().expect("Invalid amount in UTXO");
													let owner = utxo_value["address"].as_str().expect("Invalid amount in UTXO");
													if owner != sender_address {
														required_amount = 9999999999999999;
														break;
													}
													total_inputs_amount += amount;
												} else {
													required_amount = 9999999999999999;
													break;
												}
											}
											
											if total_inputs_amount >= required_amount {
												store_raw_transaction(raw_tx_str.to_string());
												let b3_tx_hash = blake3::hash(&raw_tx_str.as_bytes());
												txhash = hex::encode(b3_tx_hash.as_bytes());
												print_log_message(format!("tx processed: {}", txhash), 3);
											} else {
												let b3_tx_hash = blake3::hash(&raw_tx_str.as_bytes());
												let etxhash = hex::encode(b3_tx_hash.as_bytes());
												print_log_message(format!("tx rejected: {}", etxhash), 3);
											}
										}
										Err(e) => {
											print_log_message(format!("error tx: {}", e), 2);
										}
										
									}
								}								
							}
						}
						
						
					}
					json!({"jsonrpc": "2.0", "id": id, "result": format!("{}", txhash)})
				},
				_ => {
					print_log_message(format!("recv: {}", data), 3);
					json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "The method does not exist/is not available"}})
				}
			};
			warp::reply::json(&response)
		});
	
	let mining_route = warp::path("mining")
		.and(warp::post())
		.and(remote())
		.and(warp::body::json())
		.map(move |addr: Option<std::net::SocketAddr>, data: serde_json::Value| {
			
			if let Some(addr) = addr {
				print_log_message(format!("request from: {}", addr.ip()), 4);
			} else {
				print_log_message("request from: unknown".to_string(), 4);
			}
			
			let id = data["id"].as_str().unwrap_or("unknown");
			let method = data["method"].as_str().unwrap_or("");
			let response = match method {
				"putBlock" => {
					match serde_json::from_value::<String>(data["block"].clone()) {
						Ok(block_str) => {
							match serde_json::from_str::<serde_json::Value>(&block_str) {
								Ok(block_json) => {
									let mut new_block = Block {
										height: block_json.get("height").and_then(|v| v.as_u64()).expect("Missing height"),
										hash: block_json.get("hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										prev_hash: block_json.get("prev_hash").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										timestamp: block_json.get("timestamp").and_then(|v| v.as_u64()).expect("Missing timestamp"),
										nonce: block_json.get("nonce").and_then(|v| v.as_str()).map_or_else(|| "0000000000000000".to_string(), String::from),
										transactions: block_json.get("transactions").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										miner: block_json.get("miner").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										difficulty: block_json.get("difficulty").and_then(|v| v.as_u64()).expect("Missing difficulty"),
										block_reward: block_json.get("block_reward").and_then(|v| v.as_u64()).expect("Missing block_reward"),
										state_root: block_json.get("state_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										receipts_root: block_json.get("receipts_root").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										logs_bloom: block_json.get("logs_bloom").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										extra_data: block_json.get("extra_data").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
										version: block_json.get("version").and_then(|v| v.as_u64()).map(|v| v as u32).expect("Missing version"),
										signature: block_json.get("signature").and_then(|v| v.as_str()).map_or_else(|| "".to_string(), String::from),
									};
									
									print_log_message(format!("new block: {:?}", new_block.height), 1);
									
									if let Err(e) = save_block_to_db(&mut new_block, 1) {
										eprintln!("Error saving block: {}", e);
										json!({"jsonrpc": "2.0", "id": id, "result": "error"})
									} else {
										add_block_to_history(new_block.height, new_block.timestamp, new_block.difficulty, 0);
										json!({"jsonrpc": "2.0", "id": id, "result": "ok"})
									}
								}
								Err(_) => json!({"jsonrpc": "2.0", "id": id, "result": "error"}),
							}
						}
						Err(_) => json!({"jsonrpc": "2.0", "id": id, "result": "error"}),
					}
				},
				_ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32600, "message": "The method does not exist/is not available"}}),
			};
			
			warp::reply::json(&response)
			
			
		});

	let routes = rpc_route.or(mining_route);
	warp::serve(routes).run(([0, 0, 0, 0], 22668)).await;
	Ok(())
}

async fn full_sync_blocks(pserver: String) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let client = Client::builder()
		.timeout(Duration::from_secs(5))
		.build()
		.expect("Failed to build HTTP client");
	let rpc_url = format!("http://{}:22668/rpc", pserver);
	let db = config::db();
	loop {
		let max_block_response = client.post(&rpc_url)
			.json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "xp_blockNumber", "params": [] }))
			.send()
			.await?;
		let max_block_json: serde_json::Value = max_block_response.json().await?;
		let max_block = u64::from_str_radix(max_block_json["result"].as_str().unwrap().trim_start_matches("0x"), 16)?;
		let (mut actual_height, mut _actual_hash, _) = get_latest_block_info();
		while actual_height < max_block {
			let blocks_response = client.post(&rpc_url)
				.json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "xp_getBlocks", "params": [(actual_height+1).to_string()] }))
				.send()
				.await?;
			let blocks_json: serde_json::Value = blocks_response.json().await?;
			if let Some(blocks_array) = blocks_json["result"].as_array() {
				for (_i, block) in blocks_array.iter().enumerate() {
					let first_block = block;
					let mut new_block = Block {
						height: first_block.get("height").and_then(|v| v.as_u64()).expect("REASON"),
						hash: first_block.get("hash").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						prev_hash: first_block.get("prev_hash").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						timestamp: first_block.get("timestamp").and_then(|v| v.as_u64()).expect("REASON"),
						nonce: first_block.get("nonce").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("0000000000000000")),
						transactions: first_block.get("transactions").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						miner: first_block.get("miner").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						difficulty: first_block.get("difficulty").and_then(|v| v.as_u64()).expect("REASON"),
						block_reward: first_block.get("block_reward").and_then(|v| v.as_u64()).expect("REASON"),
						state_root: first_block.get("state_root").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						receipts_root: first_block.get("receipts_root").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						logs_bloom: first_block.get("logs_bloom").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						extra_data: first_block.get("extra_data").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
						version: first_block.get("version").and_then(|v| v.as_u64()).map(|v| v as u32).expect("REASON"),
						signature: first_block.get("signature").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_else(|| String::from("")),
					};
					let mut is_checkpoint = false;

					for checkpoint in CHECKPOINTS.iter() {
						if new_block.height == checkpoint.height {
							is_checkpoint = true;
							if new_block.hash != checkpoint.hash {
								eprintln!("block mismatch: {}!", new_block.height);
								process::exit(1);
							}
							print_log_message(format!("checkpoint block: {}", new_block.height), 1);
							break;
						}
					}

					let last_checkpoint_height = CHECKPOINTS.last().unwrap().height;

					if is_checkpoint || new_block.height <= last_checkpoint_height {
						if let Err(e) = save_block_to_db(&mut new_block, 0) {
							eprintln!("error block: {}", e);
						}
					} else {
						if let Err(e) = save_block_to_db(&mut new_block, 1) {
							eprintln!("error block: {}", e);
						}
					}
				}
			} else {
				print_log_message(format!("Sync error, stopping..."), 1);
				break;
			}
			(actual_height, _actual_hash, _) = get_latest_block_info();
			print_log_message(format!("block = {}", actual_height), 1);
		}
		break;
	}
	Ok(())
}
