extern crate ini;
extern crate rpc;
#[macro_use] extern crate jsonrpc_client_core;
extern crate jsonrpc_client_http;
extern crate hyper;
#[macro_use] extern crate serde_derive;

extern crate serde;
extern crate serde_json;

use rpc::v1::types::{ GetTxOutResponse, VerboseBlockClient, H256 as H256Json, Bytes as BytesJson, Transaction as RpcTransaction };
use std::sync::{ Arc, RwLock };
use std::thread;
use std::time::{ Duration, Instant };
use ini::Ini;
use std::collections::HashMap;
use jsonrpc_client_http::{ HttpTransport, HttpHandle };
use hyper::header::{ Authorization, Basic };

pub struct CoinConfig {
    rpcuser: String,
    rpcpassword: String,
    rpcport: u16,
    transactions: RwLock<HashMap<H256Json, RpcTransaction>>,
    block_number: RwLock<u64>
}

#[derive(Clone, Deserialize, Debug)]
pub struct UnspentOutput {
    pub txid: H256Json,
    pub vout: u32,
    pub address: String,
    pub account: String,
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: BytesJson,
    pub amount: f64,
    pub confirmations: u64,
    pub spendable: bool
}

jsonrpc_client_v1!(pub struct BitcoinClient {
    pub fn listunspent(
        &mut self,
        minconfirm: u32,
        maxconfirm: u32,
        addresses: &Vec<String>
    ) -> RpcRequest<Vec<UnspentOutput>>;
    pub fn sendrawtransaction(&mut self, tx_bytes: &BytesJson) -> RpcRequest<H256Json>;
    pub fn gettxout(&mut self, tx_id: &H256Json, index: u32) -> RpcRequest<GetTxOutResponse>;
    pub fn getblockcount(&mut self) -> RpcRequest<u64>;
    pub fn getblock(&mut self, index: &str, verbose: bool) -> RpcRequest<VerboseBlockClient>;
    pub fn getrawtransaction(&mut self, tx_id: &H256Json, verbose: u32) -> RpcRequest<RpcTransaction>;
});

pub fn create_rpc_client(coin_config: &Arc<CoinConfig>) -> BitcoinClient<HttpHandle> {
    let transport = HttpTransport::new().standalone().unwrap();
    let mut transport_handle = transport.handle(&format!("http://localhost:{}", coin_config.rpcport)).unwrap();
    transport_handle.set_header(
        Authorization(
            Basic {
                username: coin_config.rpcuser.to_owned(),
                password: Some(coin_config.rpcpassword.to_owned())
            }
        )
    );
    BitcoinClient::new(transport_handle)
}

pub fn read_coin_config(path: &'static str) -> Arc<CoinConfig> {
    let conf = Ini::load_from_file(path).unwrap();

    let section = conf.section(None::<String>).unwrap();
    let rpcuser = section.get("rpcuser").unwrap();
    let rpcpassword = section.get("rpcpassword").unwrap();
    let port = section.get("rpcport").unwrap();
    Arc::new(CoinConfig {
        rpcuser: rpcuser.clone(),
        rpcpassword: rpcpassword.clone(),
        rpcport: port.parse::<u16>().unwrap(),
        transactions: RwLock::new(HashMap::new()),
        block_number: RwLock::new(42380)
    })
}

pub fn spawn_coin_thread(coin_config: Arc<CoinConfig>) {
    thread::spawn(move || {
        loop {
            let mut rpc_client = create_rpc_client(&coin_config);
            let block_count = rpc_client.getblockcount().call().unwrap();
            let current_block_count = *coin_config.block_number.read().unwrap();
            if block_count > current_block_count {
                for block_number in current_block_count + 1..=block_count {
                    let block = rpc_client.getblock(&format!("{}", block_number), true).call().unwrap();
                    for txid in block.tx {
                        let transaction = rpc_client.getrawtransaction(&txid, 1).call();
                        match transaction {
                            Ok(tx) => { coin_config.transactions.write().unwrap().insert(tx.txid.clone(), tx); },
                            Err(_e) => ()
                        }
                    }
                }
                *coin_config.block_number.write().unwrap() = block_count;
            }
            thread::sleep(Duration::from_millis(30000));
        }
    });
}

pub fn find_tx_spend(coin_config: Arc<CoinConfig>, txid: &H256Json, index: u32) -> Result<RpcTransaction, &'static str> {
    let transactions = coin_config.transactions.read().unwrap();
    let found = transactions.iter().find(
        |(ref _x, ref y)| y.vin[0].txid == *txid && y.vin[0].vout == index
    );
    match found {
        Some((_txid, tx)) => Ok((*tx).clone()),
        None => Err("Not found")
    }
}

pub fn wait_for_tx_spend(coin_config: Arc<CoinConfig>, txid: &H256Json, index: u32) -> Result<RpcTransaction, &'static str> {
    let now = Instant::now();
    loop {
        thread::sleep(Duration::from_millis(3000));
        match find_tx_spend(coin_config.clone(), txid, index) {
            Ok(tx) => break Ok(tx),
            Err(_e) => {
                if now.elapsed().as_secs() > 60 {
                    break Err("Could not find transaction spending tx")
                }
            }
        }
    }
}
