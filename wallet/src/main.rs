use std::fs;
use std::path::Path;
use std::io::{self, Write, stdin, stdout};
use pqcrypto_sphincsplus::sphincssha2128fsimple::{
    keypair, detached_sign, verify_detached_signature,
    PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SecretKey as SecretKeyTrait, DetachedSignature};
use reqwest::blocking::Client;
use reqwest::Client as NBClient;
use reqwest::header;
use serde_json::{json, Value};
use serde::{Serialize, Deserialize};
use bincode;

use blake3;
use hex::{encode, decode};
use dialoguer::{Input, Select, Confirm};

use rusqlite::{params, Connection, Result};
use std::sync::mpsc;
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use std::sync::Mutex;
use once_cell::sync::Lazy;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::env;

use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use rand::RngCore;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use sha2::Sha256;
use dialoguer::Password;

pub static WALLET_PK: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
pub static WALLET_SK: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
pub static WALLET_ADDRESS: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
pub static WALLET_N: Lazy<Mutex<String>> = Lazy::new(|| Mutex::new(String::new()));
pub static DB_CONN: Lazy<Mutex<Option<Connection>>> = Lazy::new(|| Mutex::new(None));

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Wallet {
    name: String,
    public_key: String,
    secret_key: String,
    address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct INTXO {
    txid: String,
    vout: u32,
    extrasize: String,
    extra: String,
    sequence: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct RawTransaction {
    inputcount: String,
    inputs: Vec<INTXO>,
    outputcount: String,
    outputs: Vec<(String, u64)>,
    fee: u64,
    sigpub: String,
    signature: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Block {
    height: u64,
    hash: String,
    prev_hash: String,
    timestamp: u64,
    nonce: String,
    transactions: String,
    miner: String,
    difficulty: u64,
    block_reward: u64,
    state_root: String,
    receipts_root: String,
    logs_bloom: String,
    extra_data: String,
    version: u32,
    signature: String,
}

#[derive(Debug)]
struct UnspentUTXO {
    txid: String,
    vout: u32,
    amount: u64,
    block_hash: Option<String>,
    block_height: Option<u64>,
    status: String,
    msg: String,
    block: Option<u64>,
    ts: Option<u64>,
}

#[derive(Serialize, Debug)]
struct TxDetails {
    txid: String,
    vout: u32,
    amount: u64,
    block_hash: Option<String>,
    block_height: Option<u64>,
    status: String,
    msg: String,
    block: Option<u64>,
    ts: Option<u64>,
    direction: String,
    net_amount: Option<i64>,
    confirmations: u64,
}

fn derive_key(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key_bytes = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, 100_000, &mut key_bytes);
    Key::<Aes256Gcm>::from_slice(&key_bytes).clone()
}

fn save_wallet_encrypted(wallet: &Wallet, password: &str) -> io::Result<()> {
    let wallet_dir = "wallets";
    if !Path::new(wallet_dir).exists() {
        fs::create_dir(wallet_dir)?;
    }
    
    let filename = format!("wallets/{}.json", wallet.name);
    if Path::new(&filename).exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Wallet already exists"));
    }

    if password.is_empty() {
        let data = serde_json::to_string_pretty(wallet)?;
        fs::write(&filename, data)?;
    } else {
        let mut salt = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut salt);
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key = derive_key(password, &salt);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let wallet_json = serde_json::to_vec(wallet)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        
        let ciphertext = cipher.encrypt(nonce, wallet_json.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let mut file_data = Vec::new();
        file_data.extend_from_slice(&salt);
        file_data.extend_from_slice(&nonce_bytes);
        file_data.extend_from_slice(&ciphertext);

        fs::write(&filename, file_data)?;
    }

    Ok(())
}

fn load_wallet_encrypted(name: &str, password: &str) -> io::Result<Wallet> {
    let filename = format!("wallets/{}.json", name);
    let data = fs::read(&filename)?;

    if password.is_empty() {
        let data_str = String::from_utf8(data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let wallet: Wallet = serde_json::from_str(&data_str)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(wallet)
    } else {
        if data.len() < 28 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid wallet file"));
        }

        let salt = &data[0..16];
        let nonce_bytes = &data[16..28];
        let ciphertext = &data[28..];

        let key = derive_key(password, salt);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "Invalid password"))?;

        let wallet: Wallet = serde_json::from_slice(&plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(wallet)
    }
}

fn ask_to_continue() -> bool {
    loop {
        print!("Do you want to continue? (y/n): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("Error reading input. Please try again.");
            continue;
        }

        match input.trim().to_lowercase().as_str() {
            "y" => return true,
            "n" => return false,
            _ => {
                println!("Please enter 'y' or 'n'.");
                continue;
            }
        }
    }
}

async fn start_rpc_server() {
    let listener = TcpListener::bind("127.0.0.1:44448").await.expect("Cannot bind RPC port");
    println!("\nListening for RPC on http://127.0.0.1:44448/rpc");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                let n = stream.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..n]);
                
                println!("{:?}", request);
                
                let mut t_amount: u64 = 0;
                let mut txh: String = "".to_string();
                let mut response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "-3200"}}"#);
                if let Some(start) = request.find('{') {
                    let json_body = &request[start..];
                    if let Ok(req) = serde_json::from_str::<Value>(json_body) {
                        if req["method"] == "getbalance" {
                            let db_conn_guard = DB_CONN.lock().unwrap();
                            if let Some(conn) = db_conn_guard.as_ref() {
                                let balance = get_balance(&conn);
                                let ubalance = get_unconfirmed_balance(&conn);
                                let tbalance = ubalance + balance;                            

                                response = format!(
                                    r#"{{"jsonrpc": "2.0","id": "0","result": {{"balance": {},"blocks_to_unlock": 0,"multisig_import_needed": false,"per_subaddress": [],"time_to_unlock": 0,"unlocked_balance": {}}}}}"#,
                                    tbalance, balance
                                );
                            } else {
                                response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "No wallet database available"}}"#);
                            }
                        }
                        if req["method"] == "transfer" {
                            if let Some(destinations) = req["params"]["destinations"].as_array() {
                                let mut cmd = String::from("");
                                for dest in destinations {
                                    if let (Some(addr), Some(amount)) = (
                                        dest.get("address").and_then(|a| a.as_str()),
                                        dest.get("amount").and_then(|a| a.as_u64()),
                                    ) {
                                        t_amount += amount;
                                        let amount_xpara = amount as f64 / 100_000_000.0;
                                        cmd.push_str(&format!(" {} {:.8}", addr, amount_xpara));
                                    }
                                }
                                println!("\n[RPC] Injecting command: {}", cmd);
                                
                                let addresses: Vec<&str> = cmd.split_whitespace().collect();

                                if addresses.len() % 2 != 0 || addresses.is_empty() {
                                    println!("\nInvalid send command. Usage: send <addr1> <amount1> [addr2 amount2 ...]");
                                }
                                
                                let wallet_name_global = WALLET_N.lock().unwrap();
                                let pk = WALLET_PK.lock().unwrap();
                                let sk = WALLET_SK.lock().unwrap();
                                let w_address = WALLET_ADDRESS.lock().unwrap();
                                
                                let db_conn_guard = DB_CONN.lock().unwrap();
                                if let Some(conn) = db_conn_guard.as_ref() {
                                    let mut dest_addresses = Vec::new();
                                    let mut amounts = Vec::new();
                                    let mut total_amount = 0u64;

                                    for chunk in addresses.chunks(2) {
                                        let address = chunk[0];
                                        
                                        if address.len() != 64 || address.chars().any(|c| !c.is_ascii_hexdigit()) {
                                            println!("\nInvalid address: {} (must be 64-character hex string)", address);
                                        }
                                        
                                        let amount: f64 = match chunk[1].parse::<f64>() {
                                            Ok(num) => num,
                                            Err(_) => {
                                                println!("\nInvalid amount: {}", chunk[1]);
                                                0.0
                                            }
                                        };
                                        let f_amount: f64 = amount * 100000000.0;
                                        let i_amount: u64 = f_amount as u64;
                                        dest_addresses.push(address);
                                        amounts.push(i_amount);
                                        total_amount += i_amount;
                                    }

                                    if amounts.is_empty() {
                                        println!("\nNo valid amounts provided");
                                    }

                                    match get_unspent_utxos(&conn) {
                                        Ok(utxos) => {
                                            let fee_per_input = 5000;
                                            let fee_per_output = 2000;
                                            
                                            let output_count = dest_addresses.len() + 1;
                                            let mut fee_estimate = fee_per_input + (output_count as u64 * fee_per_output);
                                            
                                            let (selected_utxos, total_inputs, actual_fee) = select_utxos(&utxos, total_amount, fee_per_input);
                                            
                                            if selected_utxos.is_empty() {
                                                println!("\nNot enough funds or no UTXOs available");
                                            }
                                            
                                            let exact_fee = (selected_utxos.len() as u64 * fee_per_input) + (output_count as u64 * fee_per_output);
                                            
                                            if total_inputs < total_amount + exact_fee {
                                                println!("\nNot enough funds when including exact fees");
                                                println!("- Needed: {} (amount) + {} (fees) = {}", 
                                                    total_amount, exact_fee, total_amount + exact_fee);
                                                println!("- Available: {}", total_inputs);
                                            }

                                            let (inputs, outputs, fee) = build_transaction(
                                                &selected_utxos,
                                                amounts,
                                                exact_fee,
                                                dest_addresses,
                                                &w_address,
                                            );

                                            println!("\nOutputs:");
                                            for output in &outputs {
                                                println!("- {} -> {} xPARA", 
                                                    output.0, output.1 as f64 / 100000000.0);
                                            }

                                            println!("\nFee: {} xPARA ({} inputs × {} + {} outputs × {})", 
                                                fee as f64 / 100000000.0,
                                                selected_utxos.len(), fee_per_input,
                                                output_count, fee_per_output);

                                            let mut raw_tx = RawTransaction {
                                                inputcount: format!("{:02x}", inputs.len()),
                                                inputs: inputs.iter().map(|(txid, vout, _)| {
                                                    INTXO {
                                                        txid: txid.clone(),
                                                        vout: *vout,
                                                        extrasize: "00".to_string(),
                                                        extra: "".to_string(),
                                                        sequence: 0xFFFFFFFF,
                                                    }
                                                }).collect(),
                                                outputcount: format!("{:02x}", outputs.len()),
                                                outputs: outputs.clone(),
                                                fee: exact_fee,
                                                sigpub: pk.to_string(),
                                                signature: "".to_string(),
                                            };
                                            let tx_binary = bincode::serialize(&raw_tx)
                                                .expect("Failed to serialize transaction");
                                            let tx_hash = blake3::hash(&tx_binary);
                                            
                                            let sk_bytes = decode(&*sk).expect("Invalid pubkey");
                                            let ssk = SecretKey::from_bytes(&sk_bytes).expect("Invalid pubkey format");
                                            
                                            let signature = detached_sign(tx_hash.as_bytes(), &ssk);
                                            let signature_hex = encode(signature.as_bytes());
                                            raw_tx.signature = signature_hex;
                                            let signed_tx_binary = bincode::serialize(&raw_tx)
                                                .expect("Failed to serialize signed transaction");
                                            let signed_tx_hex = encode(&signed_tx_binary);
                                            println!("\nTransaction signed successfully");
                                            let th = blake3::hash(signed_tx_hex.as_bytes());
                                            txh = hex::encode(th.as_bytes());
                                            println!("Transaction ID: {}", txh);
                                            println!("\nBroadcasting transaction...");

                                            let send_request = json!({
                                                "jsonrpc": "2.0",
                                                "id": "xpara",
                                                "method": "xp_sendRawTransaction",
                                                "params": [signed_tx_hex]
                                            });
                                            
                                            let client = Client::builder()
                                                .build()
                                                .expect("Error creating HTTP client");
                                            
                                            match client.post("http://localhost:22668/rpc")
                                                .header(header::CONTENT_TYPE, "application/json")
                                                .json(&send_request)
                                                .send() {
                                                    Ok(resp) => {
                                                        if let Ok(response_text) = resp.text() {
                                                            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                                                                if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                                                                    if result == txh {
                                                                        response = format!(
                                                                            r#"{{"jsonrpc": "2.0","id": "0","result": {{"amount": {},"fee": 1000000,"multisig_txset": "","tx_blob": "","tx_hash": "{}","tx_key": "{}","tx_metadata": "","unsigned_txset": ""}}}}"#,
                                                                            t_amount, txh, txh
                                                                        );
                                                                        println!("\nTransaction sent successfully");

                                                                        for (txid, vout, _) in inputs {
                                                                            conn.execute(
                                                                                "UPDATE inputs SET status = 'spent' WHERE txid = ?1 AND vout = ?2",
                                                                                params![txid, vout],
                                                                            ).expect("Failed to update input status");
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    },
                                                    Err(e) => println!("\nError sending transaction: {}", e),
                                                }
                                        }
                                        Err(e) => println!("\nError fetching UTXOs: {}", e),
                                    }
                                } else {
                                    response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "No wallet database available"}}"#);
                                }
                            }
                        }
                        if req["method"] == "transferm" {
                            if let (Some(address), Some(amount), Some(message)) = (
                                req["params"]["address"].as_str(),
                                req["params"]["amount"].as_u64(),
                                req["params"]["message"].as_str(),
                            ) {
                                t_amount = amount;
                                println!("\n[RPC] Injecting transferm command: {} {} {}", address, amount, message);
                                
                                let wallet_name_global = WALLET_N.lock().unwrap();
                                let pk = WALLET_PK.lock().unwrap();
                                let sk = WALLET_SK.lock().unwrap();
                                let w_address = WALLET_ADDRESS.lock().unwrap();
                                
                                let db_conn_guard = DB_CONN.lock().unwrap();
                                if let Some(conn) = db_conn_guard.as_ref() {
                                    let dest_addresses = vec![address];
                                    let amounts = vec![amount];
                                    let total_amount = amount;

                                    if !address.starts_with("xP") || address.len() != 64 || address.chars().skip(2).any(|c| !c.is_ascii_hexdigit()) {
                                        println!("\nInvalid address: {}", address);
                                        response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Invalid address"}}"#);
                                    } else {
                                        match get_unspent_utxos(&conn) {
                                            Ok(utxos) => {
                                                let fee_per_input = 5000;
                                                let fee_per_output = 2000;
                                                
                                                let output_count = dest_addresses.len() + 1;
                                                let mut fee_estimate = fee_per_input + (output_count as u64 * fee_per_output);
                                                
                                                let (selected_utxos, total_inputs, actual_fee) = select_utxos(&utxos, total_amount, fee_per_input);
                                                
                                                if selected_utxos.is_empty() {
                                                    println!("\nNot enough funds or no UTXOs available");
                                                    response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Not enough funds"}}"#);
                                                } else {
                                                    let exact_fee = (selected_utxos.len() as u64 * fee_per_input) + (output_count as u64 * fee_per_output);
                                                    
                                                    if total_inputs < total_amount + exact_fee {
                                                        println!("\nNot enough funds when including exact fees");
                                                        println!("- Needed: {} (amount) + {} (fees) = {}", 
                                                            total_amount, exact_fee, total_amount + exact_fee);
                                                        println!("- Available: {}", total_inputs);
                                                        response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Not enough funds including fees"}}"#);
                                                    } else {
                                                        let (inputs, outputs, fee) = build_transaction(
                                                            &selected_utxos,
                                                            amounts,
                                                            exact_fee,
                                                            dest_addresses.clone(),
                                                            &w_address,
                                                        );

                                                        println!("\nOutputs:");
                                                        for output in &outputs {
                                                            println!("- {} -> {} xPARA", 
                                                                output.0, output.1 as f64 / 100000000.0);
                                                        }

                                                        println!("\nFee: {} xPARA ({} inputs × {} + {} outputs × {})", 
                                                            fee as f64 / 100000000.0,
                                                            selected_utxos.len(), fee_per_input,
                                                            output_count, fee_per_output);

                                                        let mut raw_tx = RawTransaction {
                                                            inputcount: format!("{:02x}", inputs.len()),
                                                            inputs: inputs.iter().map(|(txid, vout, _)| {
                                                                INTXO {
                                                                    txid: txid.clone(),
                                                                    vout: *vout,
                                                                    extrasize: "00".to_string(),
                                                                    extra: message.to_string(),
                                                                    sequence: 0xFFFFFFFF,
                                                                }
                                                            }).collect(),
                                                            outputcount: format!("{:02x}", outputs.len()),
                                                            outputs: outputs.clone(),
                                                            fee: exact_fee,
                                                            sigpub: pk.to_string(),
                                                            signature: "".to_string(),
                                                        };
                                                        let tx_binary = bincode::serialize(&raw_tx)
                                                            .expect("Failed to serialize transaction");
                                                        let tx_hash = blake3::hash(&tx_binary);
                                                        
                                                        let sk_bytes = decode(&*sk).expect("Invalid pubkey");
                                                        let ssk = SecretKey::from_bytes(&sk_bytes).expect("Invalid pubkey format");
                                                        
                                                        let signature = detached_sign(tx_hash.as_bytes(), &ssk);
                                                        let signature_hex = encode(signature.as_bytes());
                                                        raw_tx.signature = signature_hex;
                                                        let signed_tx_binary = bincode::serialize(&raw_tx)
                                                            .expect("Failed to serialize signed transaction");
                                                        let signed_tx_hex = encode(&signed_tx_binary);
                                                        println!("\nTransaction signed successfully");
                                                        let th = blake3::hash(signed_tx_hex.as_bytes());
                                                        txh = hex::encode(th.as_bytes());
                                                        println!("Transaction ID: {}", txh);
                                                        println!("\nBroadcasting transaction...");

                                                        let send_request = json!({
                                                            "jsonrpc": "2.0",
                                                            "id": "xpara",
                                                            "method": "xp_sendRawTransaction",
                                                            "params": [signed_tx_hex]
                                                        });
                                                        
                                                        let client = Client::builder()
                                                            .build()
                                                            .expect("Error creating HTTP client");
                                                        
                                                        match client.post("http://localhost:22668/rpc")
                                                            .header(header::CONTENT_TYPE, "application/json")
                                                            .json(&send_request)
                                                            .send() {
                                                                Ok(resp) => {
                                                                    if let Ok(response_text) = resp.text() {
                                                                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                                                                            if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                                                                                if result == txh {
                                                                                    response = format!(
                                                                                        r#"{{"jsonrpc": "2.0","id": "0","result": {{"amount": {},"fee": 1000000,"multisig_txset": "","tx_blob": "","tx_hash": "{}","tx_key": "{}","tx_metadata": "","unsigned_txset": ""}}}}"#,
                                                                                        t_amount, txh, txh
                                                                                    );
                                                                                    println!("\nTransaction sent successfully");

                                                                                    for (txid, vout, _) in inputs {
                                                                                        conn.execute(
                                                                                            "UPDATE inputs SET status = 'spent' WHERE txid = ?1 AND vout = ?2",
                                                                                            params![txid, vout],
                                                                                        ).expect("Failed to update input status");
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                },
                                                                Err(e) => println!("\nError sending transaction: {}", e),
                                                            }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                println!("\nError fetching UTXOs: {}", e);
                                                response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Error fetching UTXOs"}}"#);
                                            }
                                        }
                                    }
                                } else {
                                    response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "No wallet database available"}}"#);
                                }
                            } else {
                                response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Invalid parameters for transferm"}}"#);
                            }
                        }
						if req["method"] == "get_transactions" {
							let db_conn_guard = DB_CONN.lock().unwrap();
							if let Some(conn) = db_conn_guard.as_ref() {
								let current_block = get_last_block(conn);
								match get_all_transactions(conn, current_block) {
									Ok(transactions) => {
										response = serde_json::to_string(&json!({
											"jsonrpc": "2.0",
											"id": "0",
											"result": transactions
										})).unwrap();
									}
									Err(e) => {
										response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Error fetching transactions: {}"}}"#, e);
									}
								}
							} else {
								response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "No wallet database available"}}"#);
							}
						}

						if req["method"] == "get_transaction" {
							if let Some(txid) = req["params"]["txid"].as_str() {
								let db_conn_guard = DB_CONN.lock().unwrap();
								if let Some(conn) = db_conn_guard.as_ref() {
									let current_block = get_last_block(conn);
									match get_transaction_by_txid(conn, txid, current_block) {
										Ok(Some(transaction)) => {
											response = serde_json::to_string(&json!({
												"jsonrpc": "2.0",
												"id": "0",
												"result": transaction
											})).unwrap();
										}
										Ok(None) => {
											response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Transaction not found: {}"}}"#, txid);
										}
										Err(e) => {
											response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Error fetching transaction: {}"}}"#, e);
										}
									}
								} else {
									response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "No wallet database available"}}"#);
								}
							} else {
								response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Missing txid parameter"}}"#);
							}
						}

						if req["method"] == "get_transactions_by_msg" {
							if let Some(msg) = req["params"]["msg"].as_str() {
								let db_conn_guard = DB_CONN.lock().unwrap();
								if let Some(conn) = db_conn_guard.as_ref() {
									let current_block = get_last_block(conn);
									match get_transactions_by_msg(conn, msg, current_block) {
										Ok(transactions) => {
											response = serde_json::to_string(&json!({
												"jsonrpc": "2.0",
												"id": "0",
												"result": transactions
											})).unwrap();
										}
										Err(e) => {
											response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Error fetching transactions by message: {}"}}"#, e);
										}
									}
								} else {
									response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "No wallet database available"}}"#);
								}
							} else {
								response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Missing msg parameter"}}"#);
							}
						}

						if req["method"] == "get_transactions_by_direction" {
							if let Some(direction) = req["params"]["direction"].as_str() {
								if direction != "in" && direction != "out" {
									response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Direction must be 'in' or 'out'"}}"#);
								} else {
									let db_conn_guard = DB_CONN.lock().unwrap();
									if let Some(conn) = db_conn_guard.as_ref() {
										let current_block = get_last_block(conn);
										match get_transactions_by_direction(conn, direction, current_block) {
											Ok(transactions) => {
												response = serde_json::to_string(&json!({
													"jsonrpc": "2.0",
													"id": "0",
													"result": transactions
												})).unwrap();
											}
											Err(e) => {
												response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Error fetching transactions by direction: {}"}}"#, e);
											}
										}
									} else {
										response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "No wallet database available"}}"#);
									}
								}
							} else {
								response = format!(r#"{{"jsonrpc": "2.0","id": "0","error": "Missing direction parameter"}}"#);
							}
						}
                    }
                }
                println!("{:?}", response);
                
                let http_response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    response.len(),
                    response
                );

                let _ = stream.write_all(http_response.as_bytes()).await;
            });
        }
    }
}

fn init_wallet_db(wallet_name: &str) -> Result<Connection> {
    let db_path = format!("wallets/{}.dat", wallet_name);
    let conn = Connection::open(db_path)?;

    let table_exists = conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='inputs'",
        [],
        |_| Ok(()),
    ).is_ok();

    if table_exists {
        let mut has_msg = false;
        let mut has_block = false;
        let mut has_ts = false;

        let mut stmt = conn.prepare("PRAGMA table_info(inputs)")?;
        let columns = stmt.query_map([], |row| {
            let name: String = row.get(1)?;
            Ok(name)
        })?;

        for column in columns {
            let column_name = column?;
            match column_name.as_str() {
                "msg" => has_msg = true,
                "block" => has_block = true,
                "ts" => has_ts = true,
                _ => {}
            }
        }

        if !has_msg || !has_block || !has_ts {
            println!("Detected old wallet database. Migrating to new format...");
            let last_block: u64 = get_last_block(&conn);
            let utxos = get_unspent_utxos(&conn).unwrap_or_else(|_| Vec::new());
            conn.execute("DROP TABLE IF EXISTS inputs", [])?;
            conn.execute("DROP TABLE IF EXISTS meta", [])?;
            conn.execute(
                "CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )",
                [],
            )?;

            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('last_block', '1')",
                [],
            )?;
            
            conn.execute(
				"CREATE TABLE IF NOT EXISTS inputs (
					txid TEXT,
					vout INTEGER,
					amount INTEGER,
					status TEXT,
					block_hash TEXT,
					block_height INTEGER,
					msg TEXT,
					block INTEGER,
					ts INTEGER,
					direction TEXT,
					net_amount INTEGER,
					PRIMARY KEY (txid, vout)
				)",
				[],
			)?;

            update_last_block(&conn, last_block);
            
            println!("Migration completed. Wallet will resync from block {}", last_block);
        }
    } else {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )",
            [],
        )?;

        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('last_block', '1')",
            [],
        )?;
        
        conn.execute(
			"CREATE TABLE IF NOT EXISTS inputs (
				txid TEXT,
				vout INTEGER,
				amount INTEGER,
				status TEXT,
				block_hash TEXT,
				block_height INTEGER,
				msg TEXT,
				block INTEGER,
				ts INTEGER,
				direction TEXT,
				net_amount INTEGER,
				PRIMARY KEY (txid, vout)
			)",
			[],
		)?;
    }

    Ok(conn)
}

fn map_row_to_txdetails(row: &rusqlite::Row, current_block: u64) -> Result<TxDetails, rusqlite::Error> {
    let block_height: Option<u64> = row.get(4)?;
    let confirmations = if let Some(bh) = block_height {
        current_block.saturating_sub(bh)
    } else {
        0
    };
    
    Ok(TxDetails {
        txid: row.get(0)?,
        vout: row.get(1)?,
        amount: row.get(2)?,
        block_hash: row.get(3)?,
        block_height,
        status: row.get(5)?,
        msg: row.get(6)?,
        block: row.get(7)?,
        ts: row.get(8)?,
        direction: row.get(9)?,
        net_amount: row.get(10)?,
        confirmations,
    })
}

fn get_last_block(conn: &Connection) -> u64 {
    conn.query_row(
        "SELECT value FROM meta WHERE key = 'last_block'",
        [],
        |row| row.get::<_, String>(0),
    )
    .ok()
    .and_then(|s| s.parse().ok())
    .unwrap_or(1)
}

fn refresh_utxos(conn: &Connection) -> u64 {
    let start_block: String = Input::new()
        .with_prompt("From which block do you want to refresh? (press Enter to start from block 1)")
        .allow_empty(true)
        .default("1".to_string())
        .interact_text()
        .unwrap();

    let start_block = start_block.parse().unwrap_or(1);

    let _ = conn.execute(
        "DELETE FROM inputs", []
    );
    
    let _ = conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'last_block'",
        params![start_block.to_string()],
    );

    start_block
}

fn update_last_block(conn: &Connection, height: u64) {
    let _ = conn.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'last_block'",
        params![height.to_string()],
    );
}

fn insert_input(
    conn: &Connection, 
    txid: &str, 
    vout: u32, 
    amount: u64, 
    status: &str,
    block_hash: Option<&str>,
    block_height: Option<u64>,
    msg: Option<&str>,
    block: Option<u64>,
    ts: Option<u64>,
    direction: Option<&str>,
    net_amount: Option<i64>,
) {
    let _ = conn.execute(
        "INSERT OR IGNORE INTO inputs (txid, vout, amount, status, block_hash, block_height, msg, block, ts, direction, net_amount) 
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            txid, 
            vout, 
            amount, 
            status,
            block_hash,
            block_height,
            msg.unwrap_or(""),
            block,
            ts,
            direction.unwrap_or(""),
            net_amount
        ],
    );
}

fn get_balance(conn: &Connection) -> u64 {
    conn.query_row(
        "SELECT SUM(amount) FROM inputs WHERE status IN ('unspent')",
        [],
        |row| row.get::<_, u64>(0),
    )
    .unwrap_or(0)
}

fn get_unconfirmed_balance(conn: &Connection) -> u64 {
    conn.query_row(
        "SELECT SUM(amount) FROM inputs WHERE status IN ('unconfirmed')",
        [],
        |row| row.get::<_, u64>(0),
    )
    .unwrap_or(0)
}

fn get_unspent_utxos(conn: &Connection) -> Result<Vec<UnspentUTXO>> {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, amount, block_hash, block_height, status, msg, block, ts
         FROM inputs 
         WHERE status IN ('unspent') 
         ORDER BY amount DESC"
    )?;
    
    let utxo_iter = stmt.query_map([], |row| {
        Ok(UnspentUTXO {
            txid: row.get(0)?,
            vout: row.get(1)?,
            amount: row.get(2)?,
            block_hash: row.get(3)?,
            block_height: row.get(4)?,
            status: row.get(5)?,
            msg: row.get(6)?,
            block: row.get(7)?,
            ts: row.get(8)?,
        })
    })?;

    let mut utxos = Vec::new();
    for utxo in utxo_iter {
        utxos.push(utxo?);
    }
    Ok(utxos)
}

fn select_utxos(utxos: &[UnspentUTXO], amount: u64, fee_per_input: u64) -> (Vec<&UnspentUTXO>, u64, u64) {
    let mut best_solution = Vec::new();
    let mut best_total = 0;
    let mut best_fee = 0;

    for utxo in utxos {
        let fee = fee_per_input;
        if utxo.amount >= amount + fee {
            return (vec![utxo], utxo.amount, fee);
        }
    }
    for i in 0..utxos.len() {
        let mut selected = Vec::new();
        let mut total = 0;
        let mut fee = 0;

        for j in i..utxos.len() {
            let utxo = &utxos[j];
            selected.push(utxo);
            total += utxo.amount;
            fee = selected.len() as u64 * fee_per_input;

            if total >= amount + fee {
                if best_solution.is_empty() || selected.len() < best_solution.len() {
                    best_solution = selected.clone();
                    best_total = total;
                    best_fee = fee;
                }
                break;
            }
        }
    }

    (best_solution, best_total, best_fee)
}

fn build_transaction(
    selected_utxos: &[&UnspentUTXO],
    amounts: Vec<u64>,
    fee: u64,
    dest_addresses: Vec<&str>,
    my_address: &str,
) -> (Vec<(String, u32, u64)>, Vec<(String, u64)>, u64) {
    let total_inputs: u64 = selected_utxos.iter().map(|u| u.amount).sum();
    let total_outputs: u64 = amounts.iter().sum();
    let change = total_inputs.checked_sub(total_outputs + fee).unwrap_or(0);
    
    let inputs: Vec<(String, u32, u64)> = selected_utxos
        .iter()
        .map(|u| (u.txid.clone(), u.vout, u.amount))
        .collect();

    let mut outputs = Vec::new();

    for (addr, amount) in dest_addresses.iter().zip(amounts.iter()) {
        outputs.push((addr.to_string(), *amount));
    }

    if change > 0 {
        outputs.push((my_address.to_string(), change));
    }

    (inputs, outputs, fee)
}

fn save_wallet(wallet: &Wallet) -> io::Result<()> {
    let wallet_dir = "wallets";
    if !Path::new(wallet_dir).exists() {
        fs::create_dir(wallet_dir)?;
    }
    let filename = format!("wallets/{}.json", wallet.name);
    if Path::new(&filename).exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "Wallet already exists"));
    }
    let data = serde_json::to_string_pretty(wallet)?;
    let mut file = fs::File::create(filename)?;
    file.write_all(data.as_bytes())?;
    Ok(())
}

fn load_wallet(name: &str) -> io::Result<Wallet> {
    let filename = format!("wallets/{}.json", name);
    let data = fs::read_to_string(filename)?;
    let wallet: Wallet = serde_json::from_str(&data)?;
    Ok(wallet)
}

fn list_wallets() -> io::Result<Vec<String>> {
    let wallet_dir = "wallets";
    if !Path::new(wallet_dir).exists() {
        return Ok(Vec::new());
    }
    let mut wallets = Vec::new();
    for entry in fs::read_dir(wallet_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            if let Some(stem) = path.file_stem() {
                if let Some(name) = stem.to_str() {
                    wallets.push(name.to_string());
                }
            }
        }
    }
    Ok(wallets)
}

fn get_tx_details(conn: &Connection, txid: &str) -> Result<Option<TxDetails>> {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, amount, block_hash, block_height, status, msg, block, ts, direction, net_amount
         FROM inputs 
         WHERE txid = ?1"
    )?;
    
    let mut tx_iter = stmt.query_map(params![txid], |row| {
        Ok(TxDetails {
            txid: row.get(0)?,
            vout: row.get(1)?,
            amount: row.get(2)?,
            block_hash: row.get(3)?,
            block_height: row.get(4)?,
            status: row.get(5)?,
            msg: row.get(6)?,
            block: row.get(7)?,
            ts: row.get(8)?,
            direction: row.get(9)?,
            net_amount: row.get(10)?,
			confirmations: 0,
        })
    })?;
    
    if let Some(tx) = tx_iter.next() {
        Ok(Some(tx?))
    } else {
        Ok(None)
    }
}

fn get_all_transactions(conn: &Connection, current_block: u64) -> Result<Vec<TxDetails>> {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, amount, block_hash, block_height, status, msg, block, ts, direction, net_amount 
         FROM inputs ORDER BY ts DESC"
    )?;
    
    let rows = stmt.query_map([], |row| map_row_to_txdetails(row, current_block))?;
    
    let mut transactions = Vec::new();
    for tx in rows {
        transactions.push(tx?);
    }
    Ok(transactions)
}

fn get_transaction_by_txid(conn: &Connection, txid: &str, current_block: u64) -> Result<Option<TxDetails>> {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, amount, block_hash, block_height, status, msg, block, ts, direction, net_amount
         FROM inputs WHERE txid = ?1"
    )?;
    
    let mut rows = stmt.query_map(params![txid], |row| map_row_to_txdetails(row, current_block))?;
    
    if let Some(tx) = rows.next() {
        Ok(Some(tx?))
    } else {
        Ok(None)
    }
}

fn get_transactions_by_msg(conn: &Connection, msg: &str, current_block: u64) -> Result<Vec<TxDetails>> {
    let search_msg = format!("%{}%", msg);
    let mut stmt = conn.prepare(
        "SELECT txid, vout, amount, block_hash, block_height, status, msg, block, ts, direction, net_amount 
         FROM inputs WHERE msg LIKE ?1 ORDER BY ts DESC"
    )?;
    
    let rows = stmt.query_map(params![search_msg], |row| map_row_to_txdetails(row, current_block))?;
    
    let mut transactions = Vec::new();
    for tx in rows {
        transactions.push(tx?);
    }
    Ok(transactions)
}

fn get_transactions_by_direction(conn: &Connection, direction: &str, current_block: u64) -> Result<Vec<TxDetails>> {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, amount, block_hash, block_height, status, msg, block, ts, direction, net_amount 
         FROM inputs WHERE direction = ?1 ORDER BY ts DESC"
    )?;
    
    let rows = stmt.query_map(params![direction], |row| map_row_to_txdetails(row, current_block))?;
    
    let mut transactions = Vec::new();
    for tx in rows {
        transactions.push(tx?);
    }
    Ok(transactions)
}

fn print_help() {
    println!("Available commands:");
    println!("  help          - Show this help message");
    println!("  address       - Show wallet address");
    println!("  keys          - Show wallet keys");
    println!("  balance       - Show current wallet balance");
    println!("  exit          - Exits the program");
    println!("  refresh       - Refresh wallet balances and inputs from scratch");
    println!("  send <addr1> <amount1> [addr2 amount2 ...] - Send to multiple addresses");
    println!("  unspent_utxo  - Show all unspent transaction outputs");
    println!("  print_tx <txid> - Show detailed information about a transaction");
}

fn input_thread(
    running: Arc<AtomicBool>,
    pk: PublicKey,
    sk: SecretKey,
    address: String,
) {
    while running.load(Ordering::Relaxed) {
        let mut input = String::new();
        print!("> ");
        let _ = stdout().flush();
        
        if stdin().read_line(&mut input).is_ok() {
            let input = input.trim().to_string();
            if !input.is_empty() {
                let parts: Vec<&str> = input.split_whitespace().collect();
                match parts.as_slice() {
                    ["help"] => print_help(),
					["address"] => {
						println!("\nWallet Address: {}", address);
					},
					["keys"] => {
						println!("\nPublic Key: {}", encode(pk.as_bytes()));
						println!("Private Key: {}", encode(sk.as_bytes()));
					},
                    ["balance"] => {
                        let db_conn_guard = DB_CONN.lock().unwrap();
                        if let Some(conn) = db_conn_guard.as_ref() {
                            let balance = get_balance(conn);
                            println!("\nAvailable Balance: {} xPARA", balance as f64 / 100000000.0);
                            let ubalance = get_unconfirmed_balance(conn);
                            println!("Unconfirmed Balance: {} xPARA", ubalance as f64 / 100000000.0);
                        } else {
                            println!("No wallet database available");
                        }
                    }
                    ["exit"] => {
                        println!("Closing wallet...");
                        std::process::exit(0);
                    },
					["refresh"] => {
						let db_conn_guard = DB_CONN.lock().unwrap();
						if let Some(conn) = db_conn_guard.as_ref() {
							let start_block = refresh_utxos(conn);
							println!("Database cleared. Starting sync from block {}...", start_block);
						}
					}
					["print_tx", txid] => {
						let db_conn_guard = DB_CONN.lock().unwrap();
						if let Some(conn) = db_conn_guard.as_ref() {
							match get_tx_details(conn, txid) {
								Ok(Some(tx_details)) => {
									println!("\nTransaction Details:");
									println!("TXID: {}", tx_details.txid);
									println!("Amount: {} xPARA", tx_details.amount as f64 / 100000000.0);
									println!("Vout: {}", tx_details.vout);
									println!("Direction: {}", tx_details.direction);
									if let Some(net_amount) = tx_details.net_amount {
										let sign = if net_amount >= 0 { "+" } else { "" };
										println!("Net Amount: {}{} xPARA", sign, net_amount as f64 / 100000000.0);
									}
									println!("Block: {}", tx_details.block.unwrap_or(0));
									println!("Timestamp: {}", tx_details.ts.unwrap_or(0));
									if !tx_details.msg.is_empty() {
										println!("Message: {}", tx_details.msg);
									} else {
										println!("Message: (empty)");
									}
									println!("Status: {}", tx_details.status);
									if let Some(block_hash) = tx_details.block_hash {
										println!("Block Hash: {}", block_hash);
									}
								}
								Ok(None) => {
									println!("\nTransaction not found in wallet: {}", txid);
								}
								Err(e) => {
									println!("\nError fetching transaction details: {}", e);
								}
							}
						} else {
							println!("\nNo wallet database available");
						}
					}
                    ["unspent_utxo"] => {
                        let db_conn_guard = DB_CONN.lock().unwrap();
                        if let Some(conn) = db_conn_guard.as_ref() {
                            match get_unspent_utxos(conn) {
                                Ok(utxos) => {
                                    if utxos.is_empty() {
                                        println!("\nNo unspent transaction outputs found");
                                    } else {
                                        println!("\nUnspent Transaction Outputs:");
                                        for utxo in utxos {
                                            println!(
                                                "TXID: {}, Vout: {}, Amount: {} xPARA, Status: {}",
                                                utxo.txid,
                                                utxo.vout,
                                                utxo.amount as f64 / 100000000.0,
                                                utxo.status
                                            );
                                        }
                                    }
                                }
                                Err(e) => println!("\nError fetching UTXOs: {}", e),
                            }
                        } else {
                            println!("\nNo wallet database available");
                        }
                    }
                    ["rng", low_str, high_str, count_str, deadline_str] => {
                        let low: u64 = match low_str.parse() {
                            Ok(v) => v,
                            Err(_) => { println!("\nInvalid low value: {}", low_str); continue; }
                        };
                        let high: u64 = match high_str.parse() {
                            Ok(v) => v,
                            Err(_) => { println!("\nInvalid high value: {}", high_str); continue; }
                        };
                        let count: u64 = match count_str.parse() {
                            Ok(v) => v,
                            Err(_) => { println!("\nInvalid count value: {}", count_str); continue; }
                        };
                        let deadline: u64 = match deadline_str.parse() {
                            Ok(v) => v,
                            Err(_) => { println!("\nInvalid deadline value: {}", deadline_str); continue; }
                        };

                        if count == 0 {
                            println!("\nCount must be greater than 0");
                            continue;
                        }
                        if high <= low {
                            println!("\nHigh must be greater than low");
                            continue;
                        }

                        let db_conn_guard = DB_CONN.lock().unwrap();
                        if let Some(conn) = db_conn_guard.as_ref() {
                            let mut dest_addresses = Vec::new();
                            let mut amounts = Vec::new();
                            let mut total_amount = 0u64;

                            let address = "xP0000000000000000000000000000000000000000000000000000000000000000";
                            let amount: u64 = 1 * 100_000_000;

                            dest_addresses.push(address);
                            amounts.push(amount);
                            total_amount += amount;

                            match get_unspent_utxos(conn) {
                                Ok(utxos) => {
                                    let fee_per_input = 5000;
                                    let fee_per_output = 2000;

                                    let output_count = dest_addresses.len() + 1;
                                    let mut fee_estimate = fee_per_input + (output_count as u64 * fee_per_output);

                                    let (selected_utxos, total_inputs, actual_fee) = select_utxos(&utxos, total_amount, fee_per_input);

                                    if selected_utxos.is_empty() {
                                        println!("\nNot enough funds or no UTXOs available");
                                        continue;
                                    }

                                    let exact_fee = (selected_utxos.len() as u64 * fee_per_input) + (output_count as u64 * fee_per_output);

                                    if total_inputs < total_amount + exact_fee {
                                        println!("\nNot enough funds when including exact fees");
                                        println!("- Needed: {} (amount) + {} (fees) = {}", 
                                            total_amount, exact_fee, total_amount + exact_fee);
                                        println!("- Available: {}", total_inputs);
                                        continue;
                                    }

                                    let (inputs, outputs, fee) = build_transaction(
                                        &selected_utxos,
                                        amounts,
                                        exact_fee,
                                        dest_addresses,
                                        &address,
                                    );

                                    println!("\nOutputs:");
                                    for output in &outputs {
                                        println!("- {} -> {} xPARA", 
                                            output.0, output.1 as f64 / 100_000_000.0);
                                    }

                                    println!("\nFee: {} xPARA ({} inputs × {} + {} outputs × {})", 
                                        fee as f64 / 100_000_000.0,
                                        selected_utxos.len(), fee_per_input,
                                        output_count, fee_per_output);

                                    if !ask_to_continue() {
                                        continue;
                                    }

                                    let mut raw_tx = RawTransaction {
                                        inputcount: format!("{:02x}", inputs.len()),
                                        inputs: inputs.iter().map(|(txid, vout, _)| {
                                            INTXO {
                                                txid: txid.clone(),
                                                vout: *vout,
                                                extrasize: "00".to_string(),
                                                extra: format!("rng:{},{},{},{}", low, high, count, deadline),
                                                sequence: 0xFFFFFFFF,
                                            }
                                        }).collect(),
                                        outputcount: format!("{:02x}", outputs.len()),
                                        outputs: outputs.clone(),
                                        fee: exact_fee,
                                        sigpub: encode(pk.as_bytes()),
                                        signature: "".to_string(),
                                    };

                                    let tx_binary = bincode::serialize(&raw_tx)
                                        .expect("Failed to serialize transaction");
                                    let tx_hash = blake3::hash(&tx_binary);
                                    let signature = detached_sign(tx_hash.as_bytes(), &sk);
                                    raw_tx.signature = encode(signature.as_bytes());
                                    let signed_tx_binary = bincode::serialize(&raw_tx)
                                        .expect("Failed to serialize signed transaction");
                                    let signed_tx_hex = encode(&signed_tx_binary);
                                    println!("\nTransaction signed successfully");
                                    let th = blake3::hash(signed_tx_hex.as_bytes());
                                    let txh = hex::encode(th.as_bytes());
                                    println!("Transaction ID: {}", txh);
                                    println!("\nBroadcasting transaction...");

                                    let client = Client::builder()
                                        .build()
                                        .expect("Error creating HTTP client");

                                    let send_request = json!({
                                        "jsonrpc": "2.0",
                                        "id": "xpara",
                                        "method": "xp_sendRawTransaction",
                                        "params": [signed_tx_hex]
                                    });

                                    match client.post("http://localhost:22668/rpc")
                                        .header(header::CONTENT_TYPE, "application/json")
                                        .json(&send_request)
                                        .send() {
                                            Ok(resp) => {
                                                if let Ok(response_text) = resp.text() {
                                                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
                                                        if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
                                                            if result == txh {
                                                                println!("\nTransaction sent successfully");
                                                                for (txid, vout, _) in inputs {
                                                                    conn.execute(
                                                                        "UPDATE inputs SET status = 'spent' WHERE txid = ?1 AND vout = ?2",
                                                                        params![txid, vout],
                                                                    ).expect("Failed to update input status");
                                                                }
                                                            } else {
                                                                println!("\nError sending transaction");
                                                            }
                                                        } else {
                                                            println!("\nError sending transaction");
                                                        }
                                                    } else {
                                                        println!("\nError sending transaction");
                                                    }
                                                } else {
                                                    println!("\nError sending transaction");
                                                }
                                            },
                                            Err(e) => println!("\nError sending transaction: {}", e),
                                        }
                                },
                                Err(e) => println!("\nError fetching UTXOs: {}", e),
                            }
                        } else {
                            println!("\nNo wallet database available");
                        }
                    }

                    ["send", addresses @ ..] => {
						if addresses.len() % 2 != 0 || addresses.is_empty() {
							println!("\nInvalid send command. Usage: send <addr1> <amount1> [addr2 amount2 ...]");
							continue;
						}

						let db_conn_guard = DB_CONN.lock().unwrap();
						if let Some(conn) = db_conn_guard.as_ref() {
							let mut dest_addresses = Vec::new();
							let mut amounts = Vec::new();
							let mut total_amount = 0u64;
							let mut integrated_message = String::new();

							for chunk in addresses.chunks(2) {
								let address = chunk[0];
								if address.len() == 72 && address.starts_with("xP") && addresses.len() == 2 {
									let base_address = &address[0..64];
									let message = &address[64..72];
									if base_address.chars().skip(2).all(|c| c.is_ascii_hexdigit()) && 
									   message.chars().all(|c| c.is_ascii_hexdigit()) {
										dest_addresses.push(base_address);
										integrated_message = message.to_string();
									} else {
										println!("\nInvalid integrated address: {} (must be hexadecimal)", address);
										continue;
									}
								}
								else if address.len() == 64 && address.starts_with("xP") && 
										address.chars().skip(2).all(|c| c.is_ascii_hexdigit()) {
									
									dest_addresses.push(address);
								}
								else {
									println!("\nInvalid address: {} (must be 64-character standard address or 72-character integrated address for single recipient)", address);
									continue;
								}
								
								let amount_xpara: f64 = match chunk[1].parse() {
									Ok(amount) => amount,
									Err(_) => {
										println!("\nInvalid amount: {}", chunk[1]);
										continue;
									}
								};
								let amount = (amount_xpara * 100000000.0).round() as u64;
								
								amounts.push(amount);
								total_amount += amount;
							}

							if amounts.is_empty() {
								println!("\nNo valid amounts provided");
								continue;
							}

							if addresses.len() > 2 && !integrated_message.is_empty() {
								println!("\nIntegrated addresses (72 chars) are only allowed for single recipient transactions");
								continue;
							}

							match get_unspent_utxos(conn) {
								Ok(utxos) => {
									let fee_per_input = 5000;
									let fee_per_output = 2000;
									
									let output_count = dest_addresses.len() + 1;
									let mut fee_estimate = fee_per_input + (output_count as u64 * fee_per_output);
									
									let (selected_utxos, total_inputs, actual_fee) = select_utxos(&utxos, total_amount, fee_per_input);
									
									if selected_utxos.is_empty() {
										println!("\nNot enough funds or no UTXOs available");
										continue;
									}
									
									let exact_fee = (selected_utxos.len() as u64 * fee_per_input) + (output_count as u64 * fee_per_output);
									
									if total_inputs < total_amount + exact_fee {
										println!("\nNot enough funds when including exact fees");
										println!("- Needed: {} (amount) + {} (fees) = {}", 
											total_amount, exact_fee, total_amount + exact_fee);
										println!("- Available: {}", total_inputs);
										continue;
									}

									let (inputs, outputs, fee) = build_transaction(
										&selected_utxos,
										amounts,
										exact_fee,
										dest_addresses.clone(),
										&address,
									);

									println!("\nOutputs:");
									for output in &outputs {
										println!("- {} -> {} xPARA", 
											output.0, output.1 as f64 / 100000000.0);
									}

									println!("\nFee: {} xPARA ({} inputs × {} + {} outputs × {})", 
										fee as f64 / 100000000.0,
										selected_utxos.len(), fee_per_input,
										output_count, fee_per_output);
										
									if !ask_to_continue() {
										continue;
									}

									let mut raw_tx = RawTransaction {
										inputcount: format!("{:02x}", inputs.len()),
										inputs: inputs.iter().map(|(txid, vout, _)| {
											INTXO {
												txid: txid.clone(),
												vout: *vout,
												extrasize: "00".to_string(),
												extra: if !integrated_message.is_empty() {
													integrated_message.clone()
												} else {
													"".to_string()
												},
												sequence: 0xFFFFFFFF,
											}
										}).collect(),
										outputcount: format!("{:02x}", outputs.len()),
										outputs: outputs.clone(),
										fee: exact_fee,
										sigpub: encode(pk.as_bytes()),
										signature: "".to_string(),
									};
									let tx_binary = bincode::serialize(&raw_tx)
										.expect("Failed to serialize transaction");
									let tx_hash = blake3::hash(&tx_binary);
									let signature = detached_sign(tx_hash.as_bytes(), &sk);
									let signature_hex = encode(signature.as_bytes());
									raw_tx.signature = signature_hex;
									let signed_tx_binary = bincode::serialize(&raw_tx)
										.expect("Failed to serialize signed transaction");
									let signed_tx_hex = encode(&signed_tx_binary);
									println!("\nTransaction signed successfully");
									let th = blake3::hash(signed_tx_hex.as_bytes());
									let txh = hex::encode(th.as_bytes());
									println!("Transaction ID: {}", txh);
									println!("\nBroadcasting transaction...");
									
									let client = Client::builder()
										.build()
										.expect("Error creating HTTP client");

									let send_request = json!({
										"jsonrpc": "2.0",
										"id": "xpara",
										"method": "xp_sendRawTransaction",
										"params": [signed_tx_hex]
									});
									match client.post("http://localhost:22668/rpc")
										.header(header::CONTENT_TYPE, "application/json")
										.json(&send_request)
										.send() {
											Ok(resp) => {
												if let Ok(response_text) = resp.text() {
													if let Ok(json) = serde_json::from_str::<serde_json::Value>(&response_text) {
														if let Some(result) = json.get("result").and_then(|r| r.as_str()) {
															if result == txh {
																println!("\nTransaction sent successfully");
																for (txid, vout, _) in inputs {
																	conn.execute(
																		"UPDATE inputs SET status = 'spent' WHERE txid = ?1 AND vout = ?2",
																		params![txid, vout],
																	).expect("Failed to update input status");
																}
															} else {
																println!("\nError sending transaction");
															}
														} else {
															println!("\nError sending transaction");
														}
													} else {
														println!("\nError sending transaction");
													}
												}  else {
													println!("\nError sending transaction");
												}
											},
											Err(e) => println!("\nError sending transaction: {}", e),
										}
								}
								Err(e) => println!("\nError fetching UTXOs: {}", e),
							}
						} else {
							println!("\nNo wallet database available");
						}
					}
                    _ => println!("\nUnknown command. Type 'help' for available commands."),
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn check_confirm_utxos(conn: &Connection) {
    let mut stmt = conn.prepare(
        "SELECT txid, vout, block_height FROM inputs 
         WHERE status = 'unconfirmed' 
         AND block_height IS NOT NULL 
         AND block_height <= (SELECT value FROM meta WHERE key = 'last_block') - 6"
    ).unwrap();
    
    let utxos = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, u64>(2)?
        ))
    }).unwrap();
    
    let client = Client::builder()
        .build()
        .expect("Error creating HTTP client");

    for utxo in utxos {
        let (txid, vout, block_height) = utxo.unwrap();
        let request = json!({
            "jsonrpc": "2.0",
            "id": "xpara",
            "method": "xp_getBlockByHeight",
            "params": [block_height.to_string()]
        });
        
        if let Ok(resp) = client.post("http://localhost:22668/rpc")
            .header(header::CONTENT_TYPE, "application/json")
            .json(&request)
            .send() 
        {
            if let Ok(response_text) = resp.text() {
                if let Ok(json_response) = serde_json::from_str::<Value>(&response_text) {
                    if let Some(result) = json_response.get("result") {
                        if let Some(block) = result.as_object() {
                            if let Some(txs) = block.get("transactions") {
                                if let Some(tx_str) = txs.as_str() {
                                    if tx_str.split('-').any(|tx| {
                                        let tx_hash = blake3::hash(tx.as_bytes());
                                        hex::encode(tx_hash.as_bytes()) == txid
                                    }) {
                                        conn.execute(
                                            "UPDATE inputs SET status = 'unspent' 
                                             WHERE txid = ?1 AND vout = ?2",
                                            params![txid, vout],
                                        ).unwrap();
                                    } else {
                                        conn.execute(
                                            "DELETE FROM inputs 
                                             WHERE txid = ?1 AND vout = ?2",
                                            params![txid, vout],
                                        ).unwrap();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    println!("\nxPARASITE CLI WALLET 1.3\n");
    
    let choices = vec![
        "Create new wallet",
        "Load from keys", 
        "Load existing wallet",
    ];
    
    let selection = Select::new()
        .with_prompt("Select an option")
        .items(&choices)
        .default(0)
        .interact()
        .unwrap();

    let (pk, sk, address, wallet_name_opt) = match selection {
        0 => {
            let name: String = loop {
                let name = Input::new()
                    .with_prompt("Name for the new wallet")
                    .interact_text()
                    .unwrap();

                if !Path::new(&format!("wallets/{}.json", name)).exists() {
                    break name;
                }
                println!("A wallet with that name already exists. Please choose another.");
            };

            let password = Password::new()
                .with_prompt("Enter password for wallet (leave empty for no encryption)")
                .with_confirmation("Confirm password", "Passwords don't match")
                .allow_empty_password(true)
                .interact()
                .unwrap();

            println!("\nGenerating new keys...");
            let (pk, sk) = keypair();
            let address_hash = blake3::hash(pk.as_bytes());
            let mut address = encode(address_hash.as_bytes());
            address.replace_range(0..2, "xP");

            let wallet = Wallet {
                name: name.clone(),
                public_key: encode(pk.as_bytes()),
                secret_key: encode(sk.as_bytes()),
                address: address.clone(),
            };

            match save_wallet_encrypted(&wallet, &password) {
                Ok(_) => {
                    if password.is_empty() {
                        println!("Wallet '{}' created successfully (UNENCRYPTED)", name);
                    } else {
                        println!("Wallet '{}' created successfully (ENCRYPTED)", name);
                    }
                }
                Err(e) => {
                    println!("Error saving wallet: {}", e);
                    std::process::exit(1);
                }
            }
            
            {
                let mut pk_global = WALLET_PK.lock().unwrap();
                *pk_global = encode(pk.as_bytes());
                
                let mut sk_global = WALLET_SK.lock().unwrap();
                *sk_global = encode(sk.as_bytes());
                
                let mut addr_global = WALLET_ADDRESS.lock().unwrap();
                *addr_global = address.clone();
            }

            (pk, sk, address, Some(name))
        }
        1 => {

			let sk_hex: String = Input::new()
				.with_prompt("Enter private key (hex)")
				.interact_text()
				.unwrap();

			if sk_hex.len() < 64 {
				println!("Error: Private key must be at least 64 characters long");
				std::process::exit(1);
			}
			
			let pk_hex = sk_hex[sk_hex.len() - 64..].to_string();
			println!("Extracted public key: {}", pk_hex);

			let name: String = loop {
				let name = Input::new()
					.with_prompt("Name for saving this wallet")
					.interact_text()
					.unwrap();

				if !Path::new(&format!("wallets/{}.json", name)).exists() {
					break name;
				}
				println!("A wallet with that name already exists. Please choose another.");
			};

			let password = Password::new()
				.with_prompt("Enter password for wallet (leave empty for no encryption)")
				.with_confirmation("Confirm password", "Passwords don't match")
				.allow_empty_password(true)
				.interact()
				.unwrap();

			let sk_bytes = match decode(&sk_hex) {
				Ok(bytes) => bytes,
				Err(_) => {
					println!("Invalid hex for private key");
					std::process::exit(1);
				}
			};

			let pk_bytes = match decode(&pk_hex) {
				Ok(bytes) => bytes,
				Err(_) => {
					println!("Invalid hex for public key");
					std::process::exit(1);
				}
			};

			let sk = match SecretKey::from_bytes(&sk_bytes) {
				Ok(key) => key,
				Err(_) => {
					println!("Failed to create SecretKey from bytes");
					std::process::exit(1);
				}
			};

			let pk = match PublicKey::from_bytes(&pk_bytes) {
				Ok(key) => key,
				Err(_) => {
					println!("Failed to create PublicKey from bytes");
					std::process::exit(1);
				}
			};

			let test_message = b"Test message for key verification";
			let test_sig = detached_sign(test_message, &sk);

			match verify_detached_signature(&test_sig, test_message, &pk) {
				Ok(_) => println!("✓ Valid key pair"),
				Err(e) => {
					println!("Error: Private and public keys don't form a valid pair");
					println!("Details: {}", e);
					std::process::exit(1);
				}
			}

			let address_hash = blake3::hash(pk.as_bytes());
			let mut address = encode(address_hash.as_bytes());
			address.replace_range(0..2, "xP");

			let wallet = Wallet {
				name: name.clone(),
				public_key: pk_hex.clone(),
				secret_key: sk_hex.clone(),
				address: address.clone(),
			};

			match save_wallet_encrypted(&wallet, &password) {
				Ok(_) => {
					if password.is_empty() {
						println!("Wallet '{}' saved successfully (UNENCRYPTED)", name);
					} else {
						println!("Wallet '{}' saved successfully (ENCRYPTED)", name);
					}
					
					{
						let mut pk_global = WALLET_PK.lock().unwrap();
						*pk_global = pk_hex;
						
						let mut sk_global = WALLET_SK.lock().unwrap();
						*sk_global = sk_hex;
						
						let mut addr_global = WALLET_ADDRESS.lock().unwrap();
						*addr_global = address.clone();
						
						let mut wallet_name_global = WALLET_N.lock().unwrap();
						*wallet_name_global = name.clone();
					}
				}
				Err(e) => {
					println!("Error saving wallet: {}", e);
					std::process::exit(1);
				}
			}

			(pk, sk, address, Some(name))
		}
        2 => {
            let wallets = match list_wallets() {
                Ok(w) if !w.is_empty() => w,
                _ => {
                    println!("No saved wallets found. Create one first.");
                    std::process::exit(1);
                }
            };

            let selection = Select::new()
                .with_prompt("Select a wallet")
                .items(&wallets)
                .interact()
                .unwrap();

            let wallet_name = &wallets[selection];

            let mut wallet = match load_wallet_encrypted(wallet_name, "") {
                Ok(w) => {
                    println!("Wallet loaded (unencrypted)");
                    w
                }
                Err(_) => {
                    let password = Password::new()
                        .with_prompt("Enter wallet password")
                        .interact()
                        .unwrap();

                    match load_wallet_encrypted(wallet_name, &password) {
                        Ok(w) => {
                            println!("Wallet loaded successfully (encrypted)");
                            w
                        }
                        Err(e) => {
                            println!("Error loading wallet: {}", e);
                            if e.kind() == io::ErrorKind::PermissionDenied {
                                println!("Invalid password or corrupted wallet file");
                            }
                            std::process::exit(1);
                        }
                    }
                }
            };

            println!("Wallet '{}' loaded successfully", wallet_name);

            let sk_bytes = decode(wallet.secret_key).expect("Invalid hex for private key");
            let pk_bytes = decode(wallet.public_key).expect("Invalid hex for public key");

            let sk = SecretKey::from_bytes(&sk_bytes).expect("Failed to create SecretKey");
            let pk = PublicKey::from_bytes(&pk_bytes).expect("Failed to create PublicKey");

            {
                let mut pk_global = WALLET_PK.lock().unwrap();
                *pk_global = encode(pk.as_bytes());
                
                let mut sk_global = WALLET_SK.lock().unwrap();
                *sk_global = encode(sk.as_bytes());
                
                let mut addr_global = WALLET_ADDRESS.lock().unwrap();
                *addr_global = wallet.address.clone();
                
                let mut wallet_name_global = WALLET_N.lock().unwrap();
                *wallet_name_global = wallet_name.clone();
            }

            (pk, sk, wallet.address, Some(wallet_name.clone()))
        }
        _ => unreachable!(),
    };

    println!("- Public key: {}", encode(pk.as_bytes()));
    println!("- Private key: {}", encode(sk.as_bytes()));
    println!("- Address: {}", address);

    let mut last_block = 1;
    if let Some(wallet_name) = &wallet_name_opt {
        let mut wallet_name_global = WALLET_N.lock().unwrap();
        *wallet_name_global = wallet_name.clone();
        let conn = init_wallet_db(wallet_name).expect("Failed to open wallet DB");
        last_block = get_last_block(&conn);
        
        let mut db_conn_global = DB_CONN.lock().unwrap();
        *db_conn_global = Some(conn);
    }
    
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let input_pk = pk.clone();
    let input_sk = sk.clone();
    let input_address = address.clone();
    
    let input_handle = thread::spawn(move || {
        input_thread(r, input_pk, input_sk, input_address);
    });
    
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|arg| arg == "--rpc") {
        tokio::spawn(async move {
            start_rpc_server().await;
        });
    }
    
	let mut xchk: u64 = 0;
	let clientb = NBClient::builder()
		.build()
		.expect("Error creating HTTP client");

	let mut showing_progress = false;
	let mut consecutive_empty_responses = 0;
	const MAX_CONSECUTIVE_EMPTY: u32 = 3;
	
	 print_help();

	loop {
		{
			let db_conn_guard = DB_CONN.lock().unwrap();
			if let Some(conn) = db_conn_guard.as_ref() {
				last_block = get_last_block(conn);
			}
		}

		{
			let db_conn_guard = DB_CONN.lock().unwrap();
			if let Some(conn) = db_conn_guard.as_ref() {
				if xchk % 7 == 6 {
					check_confirm_utxos(conn);
				}
			}
		}
		xchk += 1;

		let request = json!({
			"jsonrpc": "2.0",
			"id": "xpara",
			"method": "xp_getBlocks",
			"params": [last_block.to_string()]
		});

		let response = clientb.post("http://localhost:22668/rpc")
			.header(header::CONTENT_TYPE, "application/json")
			.json(&request)
			.send()
			.await;
			
		match response {
			Ok(resp) => {
				let response_text = match resp.text().await {
					Ok(text) => text,
					Err(_) => continue,
				};
				
				let json_response: Value = match serde_json::from_str(&response_text) {
					Ok(json) => json,
					Err(_) => continue,
				};
				
				if let Some(result) = json_response.get("result") {
					if let Some(blocks) = result.as_array() {
						if blocks.is_empty() {
							consecutive_empty_responses += 1;
							
							if showing_progress {
								if consecutive_empty_responses >= MAX_CONSECUTIVE_EMPTY {
									let clean_line = "                                                                                                 ";
									print!("\rSynced up to block: {} {}", last_block, clean_line);
									println!();
									showing_progress = false;
								} else {
									print!("\rSyncing... current block: {} (waiting for new blocks...)", last_block);
									io::stdout().flush().unwrap();
								}
							}
							std::thread::sleep(std::time::Duration::from_secs(1));
							continue;
						} else {
							consecutive_empty_responses = 0;
							
							if showing_progress {
								print!("\r");
								io::stdout().flush().unwrap();
								showing_progress = false;
							}
						}

						if showing_progress {
							print!("\r");
							io::stdout().flush().unwrap();
							showing_progress = false;
						}
						
						let mut found_outputs = false;
						
						for block in blocks {
							if let Ok(block) = serde_json::from_value::<Block>(block.clone()) {
								for tx_hex in block.transactions.split('-') {
									if let Ok(tx_bytes) = hex::decode(tx_hex.trim()) {
										let b3_tx_hash = blake3::hash(tx_hex.as_bytes());
										let tx_hash = hex::encode(b3_tx_hash.as_bytes());
										if let Ok(raw_tx) = bincode::deserialize::<RawTransaction>(&tx_bytes) {
											
											let mut total_spent: i64 = 0;
											let mut total_received: i64 = 0;

											let db_conn_guard = DB_CONN.lock().unwrap();
											if let Some(conn) = db_conn_guard.as_ref() {
												for input in &raw_tx.inputs {
													let mut stmt = conn
														.prepare("SELECT amount FROM inputs WHERE txid = ?1 AND vout = ?2")
														.expect("Failed to prepare statement");
													let mut rows = stmt
														.query(params![input.txid, input.vout])
														.expect("Failed to execute query");
													if let Some(row) = rows.next().expect("Failed to fetch row") {
														let amount: i64 = row.get(0).expect("Failed to get amount");
														total_spent += amount;
														let _ = conn.execute(
															"UPDATE inputs SET status = 'spent' WHERE txid = ?1 AND vout = ?2",
															params![input.txid, input.vout],
														);
													}
												}

												for (vout, (output_address, amount)) in raw_tx.outputs.iter().enumerate() {
													if output_address == &address {
														total_received += *amount as i64;
														let msg = if !raw_tx.inputs.is_empty() {
															Some(raw_tx.inputs[0].extra.as_str())
														} else {
															None
														};
														
														let net = total_received as i64 - total_spent as i64;
														let direction = if net >= 0 { "in" } else { "out" };
														
														insert_input(
															conn, 
															&tx_hash, 
															vout as u32, 
															*amount, 
															"unspent",
															Some(&block.hash),
															Some(block.height),
															msg,
															Some(block.height),
															Some(block.timestamp),
															Some(direction),
															Some(net),
														);
														let balance = get_balance(conn);
														found_outputs = true;
													}
												}
											}

											let net = total_received as i64 - total_spent as i64;
											if net != 0 {
												let sign = if net > 0 { "+" } else { "" };
												println!("{}: {}{} xPARA", tx_hash, sign, net as f64 / 100_000_000.0);
											}
										}
									}
								}
								
								if block.height >= last_block {
									last_block = block.height + 1;
									let db_conn_guard = DB_CONN.lock().unwrap();
									if let Some(conn) = db_conn_guard.as_ref() {
										update_last_block(conn, last_block);
										
										print!("\rSyncing... current block: {} ", block.height);
										io::stdout().flush().unwrap();
										showing_progress = true;

									}
								}
							}
						}
						if showing_progress {
							if let Some(last_block_value) = blocks.last() {
								if let Ok(block) = serde_json::from_value::<Block>(last_block_value.clone()) {
									print!("\rSyncing... current block: {} ", block.height);
									io::stdout().flush().unwrap();
								}
							}
						}
						if !found_outputs && !showing_progress {
							if let Some(last_block_value) = blocks.last() {
								if let Ok(block) = serde_json::from_value::<Block>(last_block_value.clone()) {
									print!("\rSyncing... current block: {} ", block.height);
									io::stdout().flush().unwrap();
									showing_progress = true;
								}
							}
						}
					}
				}
			}
			Err(e) => {
				if showing_progress {
					print!("\r");
					io::stdout().flush().unwrap();
					showing_progress = false;
				}
				std::thread::sleep(std::time::Duration::from_secs(1));
			}
		}

		std::thread::sleep(std::time::Duration::from_secs(1));
	}
}