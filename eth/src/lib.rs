extern crate web3;
extern crate ethabi;
extern crate ethcore_transaction;
extern crate ethereum_types;
extern crate ethkey;
extern crate rlp;
extern crate hex;

use ethcore_transaction::{ Action, Transaction };
use ethereum_types::{ U256, H160, H256 };
use ethkey::{ KeyPair };
use ethabi::{ Contract, Token, Error as EthAbiError };
use web3::futures::Future;
use web3::transports::{ Http, EventLoopHandle };
use web3::{ Web3 };
use web3::types::{ Transaction as Web3Transaction, TransactionId, BlockId, BlockNumber };
use web3::confirm::TransactionReceiptBlockNumberCheck;
use std::time::Duration;
use std::sync::{ Arc, RwLock };
use std::thread;
use std::collections::HashMap;
use std::os::raw::c_char;
use std::ffi::CString;
use std::ffi::CStr;
use std::str::FromStr;
use std::mem;

static ALICE_ABI: &'static str = r#"[{"constant":false,"inputs":[{"name":"_dealId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_bob","type":"address"},{"name":"_aliceHash","type":"bytes20"},{"name":"_bobHash","type":"bytes20"},{"name":"_tokenAddress","type":"address"}],"name":"initErc20Deal","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_dealId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_tokenAddress","type":"address"},{"name":"_alice","type":"address"},{"name":"_bobHash","type":"bytes20"},{"name":"_aliceSecret","type":"bytes"}],"name":"bobClaimsPayment","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_dealId","type":"bytes32"},{"name":"_bob","type":"address"},{"name":"_aliceHash","type":"bytes20"},{"name":"_bobHash","type":"bytes20"}],"name":"initEthDeal","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"bytes32"}],"name":"deals","outputs":[{"name":"dealHash","type":"bytes20"},{"name":"state","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_dealId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_tokenAddress","type":"address"},{"name":"_bob","type":"address"},{"name":"_aliceHash","type":"bytes20"},{"name":"_bobSecret","type":"bytes"}],"name":"aliceClaimsPayment","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]"#;
static BOB_ABI: &'static str = r#"[{"constant":true,"inputs":[{"name":"","type":"bytes32"}],"name":"payments","outputs":[{"name":"paymentHash","type":"bytes20"},{"name":"lockTime","type":"uint64"},{"name":"state","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_secret","type":"bytes32"},{"name":"_bob","type":"address"},{"name":"_tokenAddress","type":"address"}],"name":"aliceClaimsPayment","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_secret","type":"bytes32"},{"name":"_alice","type":"address"},{"name":"_tokenAddress","type":"address"}],"name":"bobClaimsDeposit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"bytes32"}],"name":"deposits","outputs":[{"name":"depositHash","type":"bytes20"},{"name":"lockTime","type":"uint64"},{"name":"state","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_bob","type":"address"},{"name":"_tokenAddress","type":"address"},{"name":"_secretHash","type":"bytes20"}],"name":"aliceClaimsDeposit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_alice","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_lockTime","type":"uint64"}],"name":"bobMakesEthPayment","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_alice","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_tokenAddress","type":"address"},{"name":"_lockTime","type":"uint64"}],"name":"bobMakesErc20Deposit","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_alice","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_tokenAddress","type":"address"},{"name":"_lockTime","type":"uint64"}],"name":"bobMakesErc20Payment","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_alice","type":"address"},{"name":"_secretHash","type":"bytes20"},{"name":"_lockTime","type":"uint64"}],"name":"bobMakesEthDeposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"_txId","type":"bytes32"},{"name":"_amount","type":"uint256"},{"name":"_alice","type":"address"},{"name":"_tokenAddress","type":"address"},{"name":"_secretHash","type":"bytes20"}],"name":"bobClaimsPayment","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"inputs":[],"payable":false,"stateMutability":"nonpayable","type":"constructor"}]"#;
static ALICE_CONTRACT: &'static str = "e1d4236c5774d35dc47dcc2e5e0ccfc463a3289c";
static BOB_CONTRACT: &'static str = "2a8e4f9ae69c86e277602c6802085febc4bd5986";

pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strs.join("")
}

pub fn extract_a_priv_m(data: Vec<u8>) -> Result<Vec<u8>, EthAbiError> {
    let abi = Contract::load(BOB_ABI.as_bytes()).unwrap();
    let alice_claims_payment = abi.function("aliceClaimsPayment").unwrap();
    let decoded = alice_claims_payment.decode_input(&data)?;
    match decoded[2] {
        Token::FixedBytes(ref bytes) => Ok(bytes.to_vec()),
        _ => panic!("Alice priv m must be fixed bytes, check the Bob contract ABI")
    }
}

pub fn extract_b_priv_n(data: Vec<u8>) -> Result<Vec<u8>, EthAbiError> {
    let abi = Contract::load(BOB_ABI.as_bytes()).unwrap();
    let alice_claims_payment = abi.function("bobClaimsDeposit").unwrap();
    let decoded = alice_claims_payment.decode_input(&data)?;
    match decoded[2] {
        Token::FixedBytes(ref bytes) => Ok(bytes.to_vec()),
        _ => panic!("Bob priv n must be fixed bytes, check the Bob contract ABI")
    }
}

#[no_mangle]
pub extern "C" fn compare_addresses(address1: *const c_char, address2: *const c_char) -> u8 {
    unsafe {
        let slice1 = CStr::from_ptr(address1).to_str().unwrap();
        let slice2 = CStr::from_ptr(address2).to_str().unwrap();
        let hash1 = H160::from_str(&slice1[2..]).unwrap();
        let hash2 = H160::from_str(&slice2[2..]).unwrap();
        (hash1 == hash2) as u8
    }
}

pub struct EthClient {
    pub web3: Web3<Http>,
    key_pair: KeyPair,
    _event_loop: EventLoopHandle,
    transactions: RwLock<HashMap<H256, Web3Transaction>>,
    block_number: RwLock<u64>
}

pub fn spawn_coin_thread(eth_client: Arc<EthClient>) {
    thread::spawn(move || {
        loop {
            let eth_block = eth_client.web3.eth().block_number().wait().unwrap();
            if *eth_client.block_number.read().unwrap() < eth_block.into() {
                for number in *eth_client.block_number.read().unwrap() + 1..=eth_block.into() {
                    let block_data = eth_client.web3.eth().block_with_txs(BlockId::Number(BlockNumber::Number(number))).wait().unwrap();
                    let mut transactions = eth_client.transactions.write().unwrap();
                    for transaction in block_data.transactions.iter() {
                        transactions.insert(transaction.hash.clone(), transaction.clone());
                    }
                }
                *eth_client.block_number.write().unwrap() = eth_block.into();
            }
            thread::sleep(Duration::from_millis(15000));
        }
    });
}

impl EthClient {
    pub fn new(secret: Vec<u8>) -> Arc<Self> {
        let (event_loop, transport) = web3::transports::Http::new("http://195.201.0.6:8545").unwrap();
        let web3 = web3::Web3::new(transport);

        let res = Arc::new(EthClient {
            web3,
            _event_loop: event_loop,
            key_pair: KeyPair::from_secret_slice(&secret).unwrap(),
            transactions: RwLock::new(HashMap::new()),
            block_number: RwLock::new(3707894)
        });
        spawn_coin_thread(res.clone());
        res
    }

    pub fn send_alice_payment_eth(
        &self,
        id: Vec<u8>,
        bob_address: Vec<u8>,
        alice_hash: Vec<u8>,
        bob_hash: Vec<u8>
    ) -> H256 {
        let abi = Contract::load(ALICE_ABI.as_bytes()).unwrap();
        let init_eth_deal = abi.function("initEthDeal").unwrap();

        let encoded = init_eth_deal.encode_input(&[
            Token::FixedBytes(id),
            Token::Address(H160::from(bob_address.as_slice())),
            Token::FixedBytes(alice_hash),
            Token::FixedBytes(bob_hash)
        ]).unwrap();
        let tx = Transaction {
            nonce: self.web3.eth().parity_next_nonce(self.key_pair.address()).wait().unwrap(),
            value: U256::from_dec_str("10000000000000000").unwrap(),
            action: Action::Call(H160::from(ALICE_CONTRACT)),
            data: encoded,
            gas: U256::from(210000),
            gas_price: U256::from_dec_str("10000000000").unwrap()
        };

        let t = tx.sign(self.key_pair.secret(), None);
        self.web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&t).to_vec())).wait().unwrap()
    }

    pub fn alice_reclaims_payment(
        &self,
        id: Vec<u8>,
        bob_address: Vec<u8>,
        alice_hash: Vec<u8>,
        bob_priv: Vec<u8>
    ) -> H256 {
        let abi = Contract::load(ALICE_ABI.as_bytes()).unwrap();
        let alice_claims_payment = abi.function("aliceClaimsPayment").unwrap();

        let encoded_claim = alice_claims_payment.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(U256::from_dec_str("10000000000000000").unwrap()),
            Token::Address(H160::new()),
            Token::Address(H160::from(bob_address.as_slice())),
            Token::FixedBytes(alice_hash),
            Token::Bytes(bob_priv)
        ]).unwrap();

        let claim_tx = Transaction {
            nonce: self.web3.eth().parity_next_nonce(self.key_pair.address()).wait().unwrap(),
            value: U256::from(0),
            action: Action::Call(H160::from(ALICE_CONTRACT)),
            data: encoded_claim,
            gas: U256::from(210000),
            gas_price: U256::from_dec_str("10000000000").unwrap()
        };

        let claim_t = claim_tx.sign(self.key_pair.secret(), None);

        self.web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&claim_t).to_vec())).wait().unwrap()
    }

    pub fn bob_spends_alice_payment(
        &self,
        id: Vec<u8>,
        alice_address: Vec<u8>,
        bob_hash: Vec<u8>,
        alice_priv: Vec<u8>
    ) -> H256 {
        let abi = Contract::load(ALICE_ABI.as_bytes()).unwrap();
        let function = abi.function("bobClaimsPayment").unwrap();

        let encoded = function.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(U256::from_dec_str("10000000000000000").unwrap()),
            Token::Address(H160::new()),
            Token::Address(H160::from(alice_address.as_slice())),
            Token::FixedBytes(bob_hash),
            Token::Bytes(alice_priv)
        ]).unwrap();

        let claim_tx = Transaction {
            nonce: self.web3.eth().parity_next_nonce(self.key_pair.address()).wait().unwrap(),
            value: U256::from(0),
            action: Action::Call(H160::from(ALICE_CONTRACT)),
            data: encoded,
            gas: U256::from(210000),
            gas_price: U256::from_dec_str("10000000000").unwrap()
        };

        let claim_t = claim_tx.sign(self.key_pair.secret(), None);

        self.web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&claim_t).to_vec())).wait().unwrap()
    }

    pub fn bob_sends_eth_deposit(
        &self,
        id: Vec<u8>,
        alice_address: Vec<u8>,
        bob_hash: Vec<u8>,
        timestamp: u64
    ) -> H256 {
        let abi = Contract::load(BOB_ABI.as_bytes()).unwrap();
        let bob_sends_eth_deposit = abi.function("bobMakesEthDeposit").unwrap();

        let encoded = bob_sends_eth_deposit.encode_input(&[
            Token::FixedBytes(id),
            Token::Address(H160::from(alice_address.as_slice())),
            Token::FixedBytes(bob_hash),
            Token::Uint(U256::from(timestamp))
        ]).unwrap();

        let tx = Transaction {
            nonce: self.web3.eth().parity_next_nonce(self.key_pair.address()).wait().unwrap(),
            value: U256::from_dec_str("10000000000000000").unwrap(),
            action: Action::Call(H160::from(BOB_CONTRACT)),
            data: encoded,
            gas: U256::from(210000),
            gas_price: U256::from_dec_str("10000000000").unwrap()
        };

        let t = tx.sign(self.key_pair.secret(), None);

        self.web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&t).to_vec())).wait().unwrap()
    }

    pub fn bob_refunds_deposit(
        &self,
        id: Vec<u8>,
        alice_address: Vec<u8>,
        bob_secret: Vec<u8>
    ) -> H256 {
        let abi = Contract::load(BOB_ABI.as_bytes()).unwrap();
        let bob_refunds_deposit = abi.function("bobClaimsDeposit").unwrap();

        let encoded = bob_refunds_deposit.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(U256::from_dec_str("10000000000000000").unwrap()),
            Token::FixedBytes(bob_secret),
            Token::Address(H160::from(alice_address.as_slice())),
            Token::Address(H160::new()),
        ]).unwrap();

        let tx = Transaction {
            nonce: self.web3.eth().parity_next_nonce(self.key_pair.address()).wait().unwrap(),
            value: U256::from(0),
            action: Action::Call(H160::from(BOB_CONTRACT)),
            data: encoded,
            gas: U256::from(210000),
            gas_price: U256::from_dec_str("10000000000").unwrap()
        };

        let t = tx.sign(self.key_pair.secret(), None);

        self.web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&t).to_vec())).wait().unwrap()
    }

    pub fn bob_sends_eth_payment(
        &self,
        id: Vec<u8>,
        alice_address: Vec<u8>,
        alice_hash: Vec<u8>,
        timestamp: u64
    ) -> H256 {
        let abi = Contract::load(BOB_ABI.as_bytes()).unwrap();
        let bob_sends_eth_payment = abi.function("bobMakesEthPayment").unwrap();

        let encoded = bob_sends_eth_payment.encode_input(&[
            Token::FixedBytes(id),
            Token::Address(H160::from(alice_address.as_slice())),
            Token::FixedBytes(alice_hash),
            Token::Uint(U256::from(timestamp))
        ]).unwrap();

        let tx = Transaction {
            nonce: self.web3.eth().parity_next_nonce(self.key_pair.address()).wait().unwrap(),
            value: U256::from_dec_str("10000000000000000").unwrap(),
            action: Action::Call(H160::from(BOB_CONTRACT)),
            data: encoded,
            gas: U256::from(210000),
            gas_price: U256::from_dec_str("10000000000").unwrap()
        };

        let t = tx.sign(self.key_pair.secret(), None);

        self.web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&t).to_vec())).wait().unwrap()
    }

    pub fn alice_claims_bob_payment(
        &self,
        id: Vec<u8>,
        alice_secret: Vec<u8>,
        bob_address: Vec<u8>
    ) -> H256 {
        let abi = Contract::load(BOB_ABI.as_bytes()).unwrap();
        let alice_claims_payment = abi.function("aliceClaimsPayment").unwrap();

        let encoded = alice_claims_payment.encode_input(&[
            Token::FixedBytes(id),
            Token::Uint(U256::from_dec_str("10000000000000000").unwrap()),
            Token::FixedBytes(alice_secret),
            Token::Address(H160::from(bob_address.as_slice())),
            Token::Address(H160::new())
        ]).unwrap();

        let tx = Transaction {
            nonce: self.web3.eth().parity_next_nonce(self.key_pair.address()).wait().unwrap(),
            value: U256::from(0),
            action: Action::Call(H160::from(BOB_CONTRACT)),
            data: encoded,
            gas: U256::from(210000),
            gas_price: U256::from_dec_str("10000000000").unwrap()
        };

        let t = tx.sign(self.key_pair.secret(), None);

        self.web3.eth().send_raw_transaction(web3::types::Bytes(rlp::encode(&t).to_vec())).wait().unwrap()
    }

    pub fn get_tx(&self, tx_id: H256) -> Web3Transaction {
        self.web3.eth().transaction(TransactionId::Hash(tx_id)).wait().unwrap().unwrap()
    }

    pub fn wait_confirm(&self, tx_id: H256) {
        let check = TransactionReceiptBlockNumberCheck::new(self.web3.eth().clone(), tx_id);
        let duration = Duration::from_secs(1);
        let wait = self.web3.wait_for_confirmations(duration, 1, check).wait();
    }

    pub fn my_address(&self) -> H160 {
        self.key_pair.address()
    }

    pub fn find_bob_tx_spend(&self, tx_id: Vec<u8>, function: &'static str) -> Result<Web3Transaction, &'static str> {
        let abi = Contract::load(BOB_ABI.as_bytes()).unwrap();
        let eth_function = abi.function(function).unwrap();
        let transactions = self.transactions.read().unwrap();
        let option = transactions.iter().find(
            |(ref _x, ref y)| {
                if y.to == Some(H160::from(BOB_CONTRACT)) {
                    if y.input.0.as_slice()[0..4] == eth_function.short_signature() {
                        let decoded = eth_function.decode_input(&y.input.0).unwrap();
                        println!("Decoded: {:?}", decoded);
                        decoded[0] == Token::FixedBytes(tx_id.clone())
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        );
        match option {
            Some((x, y)) => Ok(y.clone()),
            None => Err("Transaction spend was not found")
        }
    }
}

#[cfg(test)]
#[test]
fn test_extract_a_priv_m() {
    let data = hex::decode("113ee583d725f027f0bd236b9018b5df55120cf393d234dffcfacccbbbe61c69ce9716b6000000000000000000000000000000000000000000000000014d31d7c2c3f400273a7976a3c2a1edb8c834a7c6e8b095be0cf47d0fd0940f4b41c9652858b98b000000000000000000000000bab36286672fbdc7b250804bf6d14be0df69fa290000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let expected = hex::decode("273a7976a3c2a1edb8c834a7c6e8b095be0cf47d0fd0940f4b41c9652858b98b").unwrap();
    let actual = extract_a_priv_m(data).unwrap();
    assert_eq!(actual, expected);
}

#[cfg(test)]
#[test]
fn test_extract_b_priv_n() {
    let data = hex::decode("1f7a72f7f5b5f44354a4412f70c4e5977fff94febbb2286d40fe32cf44f5ea08070e6eab0000000000000000000000000000000000000000000000000176d8114695040037435e0d39cc1a1f3159925ec8743ec848d72c7d157458dcdac6c0b1782015860000000000000000000000004b2d0d6c2c785217457b69b922a2a9cea98f71e90000000000000000000000000000000000000000000000000000000000000000").unwrap();
    let expected = hex::decode("37435e0d39cc1a1f3159925ec8743ec848d72c7d157458dcdac6c0b178201586").unwrap();
    let actual = extract_b_priv_n(data).unwrap();
    assert_eq!(actual, expected);
}

#[cfg(test)]
#[test]
fn test_compare_addresses() {
    let address1 = CString::new("0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c").unwrap();
    let address2 = CString::new("0xe1D4236C5774D35Dc47dcc2E5E0CcFc463A3289c").unwrap();

    assert_eq!(compare_addresses(address1.as_ptr(), address2.as_ptr()), 1);

    let address1 = CString::new("0xe1d4236c5774d35dc47dcc2e5e0ccfc463a3289c").unwrap();
    let address2 = CString::new("0x2a8e4f9ae69c86e277602c6802085febc4bd5986").unwrap();

    assert_eq!(compare_addresses(address1.as_ptr(), address2.as_ptr()), 0);
}
