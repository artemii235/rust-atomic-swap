// extern crate jsonrpc_http_server;
extern crate coins;
extern crate sha2;
extern crate hex;
extern crate keys;
extern crate bitcrypto;
extern crate script;
extern crate chain;
extern crate serialization;
extern crate byteorder;
extern crate eth;

use std::time::{SystemTime, UNIX_EPOCH};
// use jsonrpc_http_server::*;
// use jsonrpc_http_server::jsonrpc_core::*;
use sha2::{ Sha256, Digest };
use hex::FromHex;
use keys::{ Secret as BitcoinSecret, Network, Private, KeyPair, Public };
use keys::bytes::{ Bytes };
use keys::generator::{ Random, Generator };
use keys::hash::{ H256, H160 as H160BTC };
use bitcrypto::{ dhash160, dhash256 };
use script::{ Opcode, Builder, Script, TransactionInputSigner, UnsignedTransactionInput, SignatureVersion };
use chain::{ TransactionOutput, TransactionInput, OutPoint, Transaction as BitcoinTransaction };
use chain::constants::{ SEQUENCE_FINAL };
use serialization::{ serialize };
use byteorder::{ LittleEndian, WriteBytesExt };
use coins::{ wait_for_tx_spend, create_rpc_client, read_coin_config, spawn_coin_thread, UnspentOutput };
use std::env;
use std::str::FromStr;
use eth::{ EthClient };

fn key_pair_from_seed(seed: &[u8]) -> KeyPair {
    let mut hasher = Sha256::new();
    hasher.input(seed);
    let mut hash = hasher.result();
    hash[0] &= 248;
    hash[31] &= 127;
    hash[31] |= 64;
    let private = Private {
        network: Network::Komodo,
        secret: H256::from(hash.as_slice()),
        compressed: true,
    };

    KeyPair::from_private(private).unwrap()
}

fn script_sig(message: &H256, key_pair: &KeyPair) -> Bytes {
    let signature = key_pair.private().sign(message).unwrap();

    let mut sig_script = Bytes::default();
    sig_script.append(&mut Bytes::from((*signature).to_vec()));
    sig_script.append(&mut Bytes::from(vec![1]));

    sig_script
}

fn script_sig_with_pub(message: &H256, key_pair: &KeyPair) -> Bytes {
    let sig_script = script_sig(message, key_pair);

    let builder = Builder::default();

    builder
        .push_data(&sig_script)
        .push_data(&key_pair.public().to_vec())
        .into_bytes()
}

fn signed_inputs(
    unspents: &Vec<UnspentOutput>,
    outputs: &Vec<TransactionOutput>,
    keypair: &KeyPair
) -> Vec<TransactionInput> {
    let mut unsigned_inputs : Vec<UnsignedTransactionInput> = vec![];
    let mut out_points : Vec<OutPoint> = vec![];
    for unspent in unspents.iter() {
        let out_point = OutPoint {
            hash: unspent.txid.reversed().into(),
            index: unspent.vout,
        };

        unsigned_inputs.push(UnsignedTransactionInput {
            previous_output: out_point.clone(),
            sequence: SEQUENCE_FINAL
        });

        out_points.push(out_point);
    }

    let input_signer = TransactionInputSigner {
        version: 1,
        lock_time: 0,
        inputs: unsigned_inputs,
        outputs: outputs.to_vec(),
    };

    let mut signed_inputs : Vec<TransactionInput> = vec![];
    for (i, _input) in input_signer.inputs.iter().enumerate() {
        let script_sig_hash = input_signer.signature_hash(
            i,
            0,
            &Script::from(unspents[i].script_pub_key.clone().to_vec()),
            SignatureVersion::Base,
            1
        );
        let script_sig = script_sig_with_pub(&script_sig_hash, keypair);
        signed_inputs.push(TransactionInput {
            sequence: SEQUENCE_FINAL,
            script_sig,
            script_witness: vec![],
            previous_output: out_points[i].clone(),
        });
    }

    signed_inputs
}

fn create_and_sign_tx(unspents: &Vec<UnspentOutput>, outputs: &Vec<TransactionOutput>, keypair: &KeyPair) -> BitcoinTransaction {
    BitcoinTransaction {
        outputs: outputs.to_vec(),
        lock_time: 0,
        inputs: signed_inputs(unspents, outputs, keypair),
        version: 1
    }
}

fn bob_deposit_script(time_lock: u32, priv_bn_hash: &H160BTC, priv_am_hash: &H160BTC, pub_b0: &Public, pub_a0: &Public) -> Script {
    let builder = Builder::default();
    let mut wtr = vec![];
    wtr.write_u32::<LittleEndian>(time_lock).unwrap();
    builder
        .push_opcode(Opcode::OP_IF)
        .push_bytes(&wtr)
        .push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(Opcode::OP_DROP)
        .push_opcode(Opcode::OP_SIZE)
        .push_bytes(&[32])
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_HASH160)
        .push_bytes(&priv_am_hash.to_vec())
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_bytes(&pub_a0.to_vec())
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ELSE)
        .push_opcode(Opcode::OP_SIZE)
        .push_bytes(&[32])
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_HASH160)
        .push_bytes(&priv_bn_hash.to_vec())
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_bytes(&pub_b0.to_vec())
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ENDIF)
        .into_script()
}

fn p2sh_tx(
    unspent: &UnspentOutput,
    key_pair: &KeyPair,
    script: &Script,
    amount: f64
) -> BitcoinTransaction {
    let diff = unspent.amount - amount - 0.00001;

    let mut outputs = vec![TransactionOutput {
        script_pubkey: Builder::build_p2sh(&dhash160(script)).into(),
        value: (amount * 100000000 as f64) as u64
    }];

    if diff > 0.0 {
        outputs.push(TransactionOutput {
            script_pubkey: Builder::build_p2pkh(&key_pair.public().address_hash()).into(),
            value: (diff * 100000000 as f64) as u64
        });
    }

    create_and_sign_tx(&vec![unspent.clone()], &outputs, key_pair)
}

fn alice_payment_script(pub_am: &Public, pub_bn: &Public) -> Script {
    let builder = Builder::default();
    builder
        .push_opcode(Opcode::OP_2)
        .push_bytes(&pub_am.to_vec())
        .push_bytes(&pub_bn.to_vec())
        .push_opcode(Opcode::OP_2)
        .push_opcode(Opcode::OP_CHECKMULTISIG)
        .into_script()
}

fn alice_payment_tx(unspent: &UnspentOutput, key_pair: &KeyPair, pub_am: &Public, pub_bn: &Public, amount: f64) -> BitcoinTransaction {
    let script = alice_payment_script(pub_am, pub_bn);
    let diff = unspent.amount - amount - 0.00001;

    let mut outputs = vec![TransactionOutput {
        script_pubkey: Builder::build_p2sh(&dhash160(&script)).into(),
        value: (amount * 100000000 as f64) as u64
    }];

    if diff > 0.0 {
        outputs.push(TransactionOutput {
            script_pubkey: Builder::build_p2pkh(&key_pair.public().address_hash()).into(),
            value: (diff * 100000000 as f64) as u64
        });
    }

    create_and_sign_tx(&vec![unspent.clone()], &outputs, key_pair)
}

fn alice_payment_spend_tx(
    prev_out: OutPoint,
    output: TransactionOutput,
    key_pair0: &KeyPair,
    key_pair1: &KeyPair
) -> BitcoinTransaction {
    let script = alice_payment_script(&key_pair0.public(), &key_pair1.public());
    let unsigned_input = UnsignedTransactionInput {
        previous_output: prev_out.clone(),
        sequence: SEQUENCE_FINAL
    };

    let transaction_signer = TransactionInputSigner {
        outputs: vec![output],
        inputs: vec![unsigned_input],
        lock_time: 0,
        version: 1
    };

    let sighash = transaction_signer.signature_hash(0, 0,&script, SignatureVersion::Base, 1);

    let sig0 = script_sig(&sighash, &key_pair0);
    let sig1 = script_sig(&sighash, &key_pair1);

    let builder = Builder::default();
    let spend_script = builder
        .push_opcode(Opcode::OP_0)
        .push_bytes(&sig0)
        .push_bytes(&sig1)
        .push_bytes(&script.to_vec())
        .into_bytes();

    BitcoinTransaction {
        outputs: transaction_signer.outputs,
        lock_time: 0,
        inputs: vec![
            TransactionInput {
                script_sig: spend_script,
                sequence: SEQUENCE_FINAL,
                script_witness: vec![],
                previous_output: prev_out
            }
        ],
        version: 1
    }
}

fn bob_payment_script(time_lock: u32, priv_am_hash: &H160BTC, pub_b1: &Public, pub_a0: &Public) -> Script {
    let builder = Builder::default();
    let mut wtr = vec![];
    wtr.write_u32::<LittleEndian>(time_lock).unwrap();
    builder
        .push_opcode(Opcode::OP_IF)
        .push_bytes(&wtr)
        .push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(Opcode::OP_DROP)
        .push_bytes(&pub_b1.to_vec())
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ELSE)
        .push_opcode(Opcode::OP_SIZE)
        .push_bytes(&[32])
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_HASH160)
        .push_bytes(&priv_am_hash.to_vec())
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_bytes(&pub_a0.to_vec())
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ENDIF)
        .into_script()
}

fn bob_deposit_spend_script(
    prev_out: OutPoint,
    output: TransactionOutput,
    key_pair: &KeyPair,
    deposit_script: &Script,
    secret: &H256
) -> Script {
    let unsigned_input = UnsignedTransactionInput {
        previous_output: prev_out.clone(),
        sequence: SEQUENCE_FINAL
    };

    let input_signer = TransactionInputSigner {
        version: 1,
        lock_time: 0,
        inputs: vec![unsigned_input],
        outputs: vec![output],
    };

    let script_sig_hash = input_signer.signature_hash(0, 0, deposit_script, SignatureVersion::Base, 1);

    let script_sig = script_sig(&script_sig_hash, key_pair);

    let builder = Builder::default();
    builder
        .push_data(&script_sig)
        .push_data(&secret.to_vec())
        .push_opcode(Opcode::OP_0)
        .push_data(deposit_script)
        .into_script()
}

fn extract_bob_priv_n(script: &Script) -> KeyPair {
    let mut secret = BitcoinSecret::default();
    for (i, instr) in script.iter().enumerate() {
        let instruction = instr.unwrap();
        if i == 1 {
            if instruction.opcode == Opcode::OP_PUSHBYTES_32 {
                secret = BitcoinSecret::from(instruction.data.unwrap());
            }
        }
    }
    KeyPair::from_private(Private {
        network: Network::Mainnet,
        secret: secret,
        compressed: true
    }).unwrap()
}

fn random_compressed_key_pair() -> KeyPair {
    let random_key = Random::new(Network::Komodo).generate().unwrap();

    KeyPair::from_private(Private {
        network: Network::Komodo,
        secret: random_key.private().secret.clone(),
        compressed: true,
    }).unwrap()
}

fn etomic_beer_swap() {
    let etomic_key_pair = key_pair_from_seed(env::var("SEED1").unwrap().as_bytes());
    let etomic_address = etomic_key_pair.address();
    let beer_config = read_coin_config("/home/artem/.komodo/BEER/BEER.conf");
    let etomic_config = read_coin_config("/home/artem/.komodo/ETOMIC/ETOMIC.conf");

    spawn_coin_thread(beer_config.clone());
    spawn_coin_thread(etomic_config.clone());

    let mut etomic_client = create_rpc_client(&etomic_config);

    let etomic_unspents = etomic_client.listunspent(
        1,
        999999,
        &vec![etomic_address.to_string()]
    ).call().unwrap();

    let beer_key_pair = key_pair_from_seed(env::var("SEED2").unwrap().as_bytes());
    let beer_address = beer_key_pair.address();

    let mut beer_client = create_rpc_client(&beer_config);

    let beer_unspents = beer_client.listunspent(
        1,
        999999,
        &vec![beer_address.to_string()]
    ).call().unwrap();

    let etomic_payment_amount = 0.1;
    let beer_payment_amount = 0.1;

    let etomic_unspent = etomic_unspents.iter().find(
        |ref x| x.amount >= etomic_payment_amount
    ).unwrap();
    let beer_unspent = beer_unspents.iter().find(
        |ref x| x.amount >= beer_payment_amount
    ).unwrap();

    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let bob_priv0 = random_compressed_key_pair();
    let bob_priv1 = random_compressed_key_pair();
    let bob_privn = random_compressed_key_pair();
    let alice_priv0 = random_compressed_key_pair();
    let alice_privm = random_compressed_key_pair();

    let script = bob_deposit_script(
        since_the_epoch.as_secs() as u32 + 1000,
        &dhash160(&*bob_privn.private().secret),
        &dhash160(&*alice_privm.private().secret),
        &bob_priv0.public(),
        &alice_priv0.public()
    );

    let bob_deposit = p2sh_tx(
        &beer_unspent,
        &beer_key_pair,
        &script,
        beer_payment_amount
    );

    let tx_send_result = beer_client.sendrawtransaction(&serialize(&bob_deposit).into()).call();
    match tx_send_result {
        Ok(res) => println!("Bob deposit tx send result: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }

    let prev_out = OutPoint {
        hash: bob_deposit.hash(),
        index: 0
    };

    let output = TransactionOutput {
        value: ((beer_payment_amount - 0.00001) * 100000000 as f64) as u64,
        script_pubkey: "76a9146d9d2b554d768232320587df75c4338ecc8bf37d88ac".into(),
    };

    let alice_payment = alice_payment_tx(
        &etomic_unspent,
        &etomic_key_pair,
        &alice_privm.public(),
        &bob_privn.public(),
        etomic_payment_amount
    );

    let alice_payment_send_res = etomic_client.sendrawtransaction(&serialize(&alice_payment).into()).call().unwrap();
    println!("Sent Alice payment: {:?}", alice_payment_send_res);

    let bob_payment_script = bob_payment_script(
        since_the_epoch.as_secs() as u32 + 1000,
        &dhash160(&*alice_privm.private().secret),
        &bob_priv1.public(),
        &alice_priv0.public()
    );

    let beer_unspents_2 = beer_client.listunspent(
        1,
        999999,
        &vec![beer_address.to_string()]
    ).call().unwrap();

    let beer_unspent_2 = beer_unspents_2.iter().find(
        |ref x| x.amount >= beer_payment_amount
    ).unwrap();

    let bob_payment_tx = p2sh_tx(&beer_unspent_2, &beer_key_pair, &bob_payment_script, beer_payment_amount);

    let bob_payment_tx_send_result = beer_client.sendrawtransaction(&serialize(&bob_payment_tx).into()).call();
    match bob_payment_tx_send_result {
        Ok(res) => println!("Bob payment tx: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }

    let prev_out_bob_payment = OutPoint {
        hash: bob_payment_tx.hash(),
        index: 0
    };

    let bob_payment_spend_output = TransactionOutput {
        value: ((beer_payment_amount - 0.00001) * 100000000 as f64) as u64,
        script_pubkey: Builder::build_p2pkh(&etomic_key_pair.public().address_hash()).into(),
    };

    let bob_payment_spend_script = bob_deposit_spend_script(
        prev_out_bob_payment.clone(),
        bob_payment_spend_output.clone(),
        &alice_priv0,
        &bob_payment_script,
        &alice_privm.private().secret
    );

    let payment_spend_tx = BitcoinTransaction {
        outputs: vec![bob_payment_spend_output],
        lock_time: 0,
        inputs: vec![
            TransactionInput {
                script_sig: bob_payment_spend_script.into(),
                sequence: SEQUENCE_FINAL,
                script_witness: vec![],
                previous_output: prev_out_bob_payment
            }
        ],
        version: 1
    };

    let spend_tx_send_result = beer_client.sendrawtransaction(&serialize(&payment_spend_tx).into()).call();
    match spend_tx_send_result {
        Ok(res) => println!("Bob payment spend tx send result: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }

    let spend_tx = wait_for_tx_spend(beer_config.clone(), &bob_payment_tx.hash().reversed().into(), 0).unwrap();
    println!("Found bob payment spend tx: {:?}", spend_tx);
    let a_priv_m_extracted = extract_bob_priv_n(&Script::from(spend_tx.vin[0].clone().script_sig.hex.to_vec()));

    let alice_prev_out = OutPoint {
        hash: alice_payment.hash(),
        index: 0
    };

    let alice_output = TransactionOutput {
        value: ((etomic_payment_amount - 0.00001) * 100000000 as f64) as u64,
        script_pubkey: "76a9146d9d2b554d768232320587df75c4338ecc8bf37d88ac".into(),
    };

    let alice_payment_spend_tx = alice_payment_spend_tx(
        alice_prev_out,
        alice_output,
        &a_priv_m_extracted,
        &bob_privn
    );

    let alice_payment_spend_send_res = etomic_client.sendrawtransaction(&serialize(&alice_payment_spend_tx).into()).call().unwrap();
    println!("Sent Alice payment spend: {:?}", alice_payment_spend_send_res);

    let bob_deposit_spend_script_1 = bob_deposit_spend_script(
        prev_out.clone(),
        output.clone(),
        &bob_priv0,
        &script,
        &bob_privn.private().secret
    );

    let deposit_spend_tx = BitcoinTransaction {
        outputs: vec![output],
        lock_time: 0,
        inputs: vec![
            TransactionInput {
                script_sig: bob_deposit_spend_script_1.into(),
                sequence: SEQUENCE_FINAL,
                script_witness: vec![],
                previous_output: prev_out
            }
        ],
        version: 1
    };

    let refund_tx_send_result = beer_client.sendrawtransaction(&serialize(&deposit_spend_tx).into()).call();
    match refund_tx_send_result {
        Ok(res) => println!("Bob deposit spend tx send result: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }
}

fn eth_beer_swap() {
    let beer_config = read_coin_config("/home/artem/.komodo/BEER/BEER.conf");

    spawn_coin_thread(beer_config.clone());

    let alice_key_pair = key_pair_from_seed(env::var("SEED1").unwrap().as_bytes());
    let bob_key_pair = key_pair_from_seed(env::var("SEED2").unwrap().as_bytes());
    let bob_address = bob_key_pair.address();

    let mut beer_client = create_rpc_client(&beer_config);

    let beer_unspents = beer_client.listunspent(
        1,
        999999,
        &vec![bob_address.to_string()]
    ).call().unwrap();

    let beer_payment_amount = 0.1;

    let beer_unspent = beer_unspents.iter().find(
        |ref x| x.amount >= beer_payment_amount
    ).unwrap();

    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");

    let bob_priv0 = random_compressed_key_pair();
    let bob_priv1 = random_compressed_key_pair();
    let bob_privn = random_compressed_key_pair();
    let alice_priv0 = random_compressed_key_pair();
    let alice_privm = random_compressed_key_pair();

    let script = bob_deposit_script(
        since_the_epoch.as_secs() as u32 + 1000,
        &dhash160(&*bob_privn.private().secret),
        &dhash160(&*alice_privm.private().secret),
        &bob_priv0.public(),
        &alice_priv0.public()
    );

    let bob_deposit = p2sh_tx(
        &beer_unspent,
        &bob_key_pair,
        &script,
        beer_payment_amount
    );

    let tx_send_result = beer_client.sendrawtransaction(&serialize(&bob_deposit).into()).call();
    match tx_send_result {
        Ok(res) => println!("Bob deposit tx send result: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }

    let prev_out = OutPoint {
        hash: bob_deposit.hash(),
        index: 0
    };

    let output = TransactionOutput {
        value: ((beer_payment_amount - 0.00001) * 100000000 as f64) as u64,
        script_pubkey: "76a9146d9d2b554d768232320587df75c4338ecc8bf37d88ac".into(),
    };

    let alice_eth_client = EthClient::new(alice_key_pair.private().secret.to_vec());
    let bob_eth_client = EthClient::new(bob_key_pair.private().secret.to_vec());

    let alice_payment_id = dhash256(&alice_key_pair.private().secret.to_vec());

    let alice_payment_tx = alice_eth_client.send_alice_payment_eth(
        alice_payment_id.to_vec(),
        bob_eth_client.my_address().to_vec(),
        dhash160(&*alice_privm.private().secret).to_vec(),
        dhash160(&*bob_privn.private().secret).to_vec(),
    );

    println!("Sent Alice payment: {:?}", alice_payment_tx);

    let bob_payment_script = bob_payment_script(
        since_the_epoch.as_secs() as u32 + 1000,
        &dhash160(&*alice_privm.private().secret),
        &bob_priv1.public(),
        &alice_priv0.public()
    );

    let beer_unspents_2 = beer_client.listunspent(
        1,
        999999,
        &vec![bob_address.to_string()]
    ).call().unwrap();

    let beer_unspent_2 = beer_unspents_2.iter().find(
        |ref x| x.amount >= beer_payment_amount
    ).unwrap();

    let bob_payment_tx = p2sh_tx(&beer_unspent_2, &bob_key_pair, &bob_payment_script, beer_payment_amount);

    let bob_payment_tx_send_result = beer_client.sendrawtransaction(&serialize(&bob_payment_tx).into()).call();
    match bob_payment_tx_send_result {
        Ok(res) => println!("Bob payment tx: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }

    let prev_out_bob_payment = OutPoint {
        hash: bob_payment_tx.hash(),
        index: 0
    };

    let bob_payment_spend_output = TransactionOutput {
        value: ((beer_payment_amount - 0.00001) * 100000000 as f64) as u64,
        script_pubkey: Builder::build_p2pkh(&alice_key_pair.public().address_hash()).into(),
    };

    let bob_payment_spend_script = bob_deposit_spend_script(
        prev_out_bob_payment.clone(),
        bob_payment_spend_output.clone(),
        &alice_priv0,
        &bob_payment_script,
        &alice_privm.private().secret
    );

    let payment_spend_tx = BitcoinTransaction {
        outputs: vec![bob_payment_spend_output],
        lock_time: 0,
        inputs: vec![
            TransactionInput {
                script_sig: bob_payment_spend_script.into(),
                sequence: SEQUENCE_FINAL,
                script_witness: vec![],
                previous_output: prev_out_bob_payment
            }
        ],
        version: 1
    };

    let spend_tx_send_result = beer_client.sendrawtransaction(&serialize(&payment_spend_tx).into()).call();
    match spend_tx_send_result {
        Ok(res) => println!("Bob payment spend tx send result: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }

    let spend_tx = wait_for_tx_spend(beer_config.clone(), &bob_payment_tx.hash().reversed().into(), 0).unwrap();
    println!("Found bob payment spend tx: {:?}", spend_tx);
    let a_priv_m_extracted = extract_bob_priv_n(&Script::from(spend_tx.vin[0].clone().script_sig.hex.to_vec()));

    let alice_payment_spend_tx = bob_eth_client.bob_spends_alice_payment(
        alice_payment_id.to_vec(),
        alice_eth_client.my_address().to_vec(),
        dhash160(&*bob_privn.private().secret).to_vec(),
        a_priv_m_extracted.private().secret.to_vec()
    );

    println!("Sent Alice payment spent: {:?}", alice_payment_spend_tx);

    let bob_deposit_spend_script_1 = bob_deposit_spend_script(
        prev_out.clone(),
        output.clone(),
        &bob_priv0,
        &script,
        &bob_privn.private().secret
    );

    let deposit_spend_tx = BitcoinTransaction {
        outputs: vec![output],
        lock_time: 0,
        inputs: vec![
            TransactionInput {
                script_sig: bob_deposit_spend_script_1.into(),
                sequence: SEQUENCE_FINAL,
                script_witness: vec![],
                previous_output: prev_out
            }
        ],
        version: 1
    };

    let refund_tx_send_result = beer_client.sendrawtransaction(&serialize(&deposit_spend_tx).into()).call();
    match refund_tx_send_result {
        Ok(res) => println!("Bob deposit spend tx send result: {:?}", res),
        Err(e) => println!("Tx send error: {:?}", e)
    }
}

fn main() {
    /*
    let mut io = IoHandler::default();
    io.add_method("say_hello", |_| {
        Ok(Value::String("hello123".into()))
    });

    let server = ServerBuilder::new(io)
        .cors(DomainsValidation::AllowOnly(vec![AccessControlAllowOrigin::Null]))
        .start_http(&"127.0.0.1:3030".parse().unwrap());
    */
    let args: Vec<String> = env::args().collect();
    match args[1].as_ref() {
        "ethbeer" => eth_beer_swap(),
        "etomicbeer" => etomic_beer_swap(),
        _ => println!("Unknown swap")
    }
}

#[cfg(test)]
#[test]
fn test_key_pair_from_seed() {
    let seed = env::var("SEED1").unwrap();
    let key_pair = key_pair_from_seed(seed.as_bytes());
    let private = Private {
        network: Network::Komodo,
        secret: H256::from_str(&env::var("PRIV1").unwrap()).unwrap(),
        compressed: true,
    };

    assert_eq!(private, *key_pair.private());
}

#[test]
fn test_script_sig_with_pub() {
    let message = "15c9de409c4b49621e0b42c2e76a8fe95f2c223b5fb55e4c041be9e945dc90ac".into();
    let private = Private {
        network: Network::Mainnet,
        secret: H256::from_str(&env::var("PRIV1").unwrap()).unwrap(),
        compressed: true,
    };

    let key_pair = KeyPair::from_private(private).unwrap();
    let script_sig = script_sig_with_pub(&message, &key_pair);

    let expected_script_sig: Bytes = "483045022100a8fbc839cc3543fb645a0d7853ccef43d6f4afd8f568364c9ff5b5fd404ed936022058bc1803374453e2b059fa2b74e85e0b5c1092d267c12ad6a3371ca38a78f22f012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3".into();
    assert_eq!(expected_script_sig, script_sig);
}

#[test]
fn test_create_and_sign_tx() {
    let unspents = vec![
        UnspentOutput {
            txid: "21fbf6bcc407768a1a462a0f26c66c0097709f9a5b8d6950a7c9deda7ad398f0".into(),
            vout: 0,
            account: "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into(),
            address: "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into(),
            amount: 0.0,
            confirmations: 0,
            script_pub_key: "76a91405aab5342166f8594baf17a7d9bef5d56744332788ac".into(),
            spendable: true,
        },
        UnspentOutput {
            txid: "bbeec21824a4f76044dbda090c8f67f4727072aed7027992777b2e8738398ef3".into(),
            vout: 1,
            account: "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into(),
            address: "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into(),
            amount: 0.0,
            confirmations: 0,
            script_pub_key: "76a91405aab5342166f8594baf17a7d9bef5d56744332788ac".into(),
            spendable: true,
        }
    ];

    let tx_output = TransactionOutput {
        script_pubkey: "76a91405aab5342166f8594baf17a7d9bef5d56744332788ac".into(),
        value: 18363431
    };

    let private = Private {
        network: Network::Mainnet,
        secret: H256::from_str(&env::var("PRIV1").unwrap()).unwrap(),
        compressed: true,
    };

    let key_pair = KeyPair::from_private(private).unwrap();


    let tx_bytes = serialize(&create_and_sign_tx(&unspents, &vec![tx_output], &key_pair));
    let expected_tx_bytes : Bytes = "0100000002f098d37adadec9a750698d5b9a9f7097006cc6260f2a461a8a7607c4bcf6fb21000000006b483045022100a8fbc839cc3543fb645a0d7853ccef43d6f4afd8f568364c9ff5b5fd404ed936022058bc1803374453e2b059fa2b74e85e0b5c1092d267c12ad6a3371ca38a78f22f012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3fffffffff38e3938872e7b77927902d7ae727072f4678f0c09dadb4460f7a42418c2eebb010000006b483045022100df59ac4c5ba8f7f4eacb667820c0474655ea0d5096191a76c3731343e69f08e602200aedb34f67899810a11f5829ef62e64b4a755670a9008a62cc6cf2d6cab93663012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ffffffff0127341801000000001976a91405aab5342166f8594baf17a7d9bef5d56744332788ac00000000".into();
    assert_eq!(expected_tx_bytes, tx_bytes);
}

#[test]
fn test_bob_deposit_script() {
    // bob deposit BEER tx: http://beer.komodochainz.info/tx/641cca6dd5806c1f8375fd5ddc24d8b9d1e8575ec73e43bb606cfa723d0fc7c8
    // bob deposit refund BEER tx: http://beer.komodochainz.info/tx/d254f9e1765273b3368222410ffd6754bf937b98b9894be5c9a8297d0ae64a9b
    let secret_bn = Bytes::from_str(&env::var("PRIV2").unwrap()).unwrap();

    let script_bytes : Bytes = "6304bb85f55ab17582012088a914d33356c6165e61f1f302a0a39a1b248842efb579882102e3b4015ba6b9c00fe87bd513b27f7857c8f95ec2e5c94bf6586d5d9e1415192fac6782012088a91459772344029b42e8bbd104dedc3bcebef12e46b088210372246d34f81a8e0ec8a11bf3ea81835bf8d33ef5e5059b8d64d075408d1d4554ac68".into();

    let time_lock : u32 = 1526039995;

    let pub_b0 = Public::from_slice(&<[u8; 33]>::from_hex("0372246d34f81a8e0ec8a11bf3ea81835bf8d33ef5e5059b8d64d075408d1d4554").unwrap()).unwrap();
    let pub_a0 = Public::from_slice(&<[u8; 33]>::from_hex("02e3b4015ba6b9c00fe87bd513b27f7857c8f95ec2e5c94bf6586d5d9e1415192f").unwrap()).unwrap();
    let script = bob_deposit_script(
        time_lock,
        &dhash160(&*secret_bn),
        &"d33356c6165e61f1f302a0a39a1b248842efb579".into(),
        &pub_b0,
        &pub_a0
    );

    assert_eq!(script_bytes, script.to_bytes());
}

#[test]
fn test_bob_payment_script() {
    // bob payment BEER tx: http://beer.komodochainz.info/tx/5f046313978dde48da124ca221cd320034b8ff8c71ceb0ae522d539b3f6d26b0
    // bob payment spent by Alice tx: http://beer.komodochainz.info/tx/2858c96be0025c459915e7023928a581795666f9eaf7943b72aa3babf6172867
    let script_bytes : Bytes = "6304d980f95ab17521031ab497fd772682c4afe1b6aa2438f4bc6f087f5edf57529370d5032340dca07cac6782012088a914fe945eff4cb6f839d247817b556ef083ce852960882102577fda0fc89e681b87bd692355eeaad69b4a5ba96bbec12f967ca4118a49af92ac68".into();

    let time_lock : u32 = 1526300889;

    let pub_b1 = Public::from_slice(&<[u8; 33]>::from_hex("031ab497fd772682c4afe1b6aa2438f4bc6f087f5edf57529370d5032340dca07c").unwrap()).unwrap();
    let pub_a0 = Public::from_slice(&<[u8; 33]>::from_hex("02577fda0fc89e681b87bd692355eeaad69b4a5ba96bbec12f967ca4118a49af92").unwrap()).unwrap();
    let script = bob_payment_script(
        time_lock,
        &"fe945eff4cb6f839d247817b556ef083ce852960".into(),
        &pub_b1,
        &pub_a0
    );

    assert_eq!(script_bytes, script.to_bytes());
}

#[test]
fn test_bob_deposit_spend_script() {
    let priv_b0 = H256::from_str(&env::var("PRIV1").unwrap()).unwrap();

    let private = Private {
        network: Network::Mainnet,
        secret: priv_b0,
        compressed: true,
    };

    let key_pair = KeyPair::from_private(private).unwrap();

    let prev_out = OutPoint {
        hash: H256::from_reversed_str("a4b2d80e0768118070f0881dfc68ac98ea88bc0a980e752bbc4a4e2612bd5ee3"),
        index: 0
    };

    let tx_output = TransactionOutput {
        script_pubkey: "76a91405aab5342166f8594baf17a7d9bef5d56744332788ac".into(),
        value: 369824000
    };

    let expected_script_bytes = Bytes::from_str(&format!("483045022100efd0659a274566dfaf7e6e49c126a02174242e4db62177b651d65ee54888f41b02200fda45508b0117fea026d427de40cb243bf54f7b5f7cb670c35da160b0dca4a60120{}004c866304029bfa5ab17582012088a91459772344029b42e8bbd104dedc3bcebef12e46b0882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac6782012088a91459772344029b42e8bbd104dedc3bcebef12e46b0882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac68", env::var("PRIV2").unwrap())).unwrap();

    let script = bob_deposit_spend_script(
        prev_out,
        tx_output,
        &key_pair,
        &"6304029bfa5ab17582012088a91459772344029b42e8bbd104dedc3bcebef12e46b0882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac6782012088a91459772344029b42e8bbd104dedc3bcebef12e46b0882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac68".into(),
        &H256::from_str(&env::var("PRIV2").unwrap()).unwrap()
    );

    assert_eq!(expected_script_bytes, script.to_bytes());
}

#[test]
fn test_alice_payment_script() {
    let expected_script_bytes : Bytes = "522102a80462ede85bddee6b3f6c92fe9380b1b1c2f85ab4dbbb100e8a204c7ce74740210388be77e8919562fee28b4e3d6150c39e3cf6c5b39da043aaa977d7dc432858e252ae".into();

    let pub_am = Public::from_slice(&<[u8; 33]>::from_hex("02a80462ede85bddee6b3f6c92fe9380b1b1c2f85ab4dbbb100e8a204c7ce74740").unwrap()).unwrap();
    let pub_bn = Public::from_slice(&<[u8; 33]>::from_hex("0388be77e8919562fee28b4e3d6150c39e3cf6c5b39da043aaa977d7dc432858e2").unwrap()).unwrap();

    let script = alice_payment_script(&pub_am, &pub_bn);

    assert_eq!(expected_script_bytes, script.to_bytes());
}

#[test]
fn test_create_alice_payment() {
    // real etomic tx: 8a6762514cd7813a458fe7cc7e1a0093e1fa19b174879ea5f74ff87c56cfe7eb
    let seed = env::var("SEED1").unwrap();
    let key_pair0 = key_pair_from_seed(seed.as_bytes());

    let priv_1 = H256::from_str(&env::var("PRIV2").unwrap()).unwrap();

    let private = Private {
        network: Network::Mainnet,
        secret: priv_1,
        compressed: true,
    };

    let key_pair1 = KeyPair::from_private(private).unwrap();

    let unspent = UnspentOutput {
        txid: "cb032c01e3a600c9952822b9c15f487ca09416dc9f1a6c9dd19fd1c49861f5ee".into(),
        vout: 1,
        address: "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into(),
        account: "R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW".into(),
        script_pub_key: "76a91405aab5342166f8594baf17a7d9bef5d56744332788ac".into(),
        spendable: true,
        confirmations: 1,
        amount: 0.02514708
    };

    let expected_tx_bytes : Bytes = "0100000001eef56198c4d19fd19d6c1a9fdc1694a07c485fc1b9222895c900a6e3012c03cb010000006b483045022100ebab444f3d75d88a059d84a8e1a6a21e0ce2fd69548fee3dd8d3d694a6f8321f02203dbf1a059f9d30e34be2d7fd3b01d04290862fafbcf27a6844589cf2ec94d102012102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ffffffff012c5b26000000000017a9142e1db0bd23e1802b13ac3373192857300575e7af8700000000".into();

    let tx_bytes = serialize(&alice_payment_tx(&unspent, &key_pair0, &key_pair0.public(), &key_pair1.public(), 0.02513708));

    assert_eq!(expected_tx_bytes, tx_bytes);
}

#[test]
fn test_create_bob_deposit() {
    // real etomic tx: 8a6762514cd7813a458fe7cc7e1a0093e1fa19b174879ea5f74ff87c56cfe7eb
    let seed = env::var("SEED2").unwrap();
    let key_pair0 = key_pair_from_seed(seed.as_bytes());

    let unspent = UnspentOutput {
        txid: "21ad095c01595ade7e9bf2c031ed738fbb820064a75b4e335541195815e37816".into(),
        vout: 1,
        address: "RKGn1jkeS7VNLfwY74esW7a8JFfLNj1Yoo".into(),
        account: "RKGn1jkeS7VNLfwY74esW7a8JFfLNj1Yoo".into(),
        script_pub_key: "76a9146d9d2b554d768232320587df75c4338ecc8bf37d88ac".into(),
        spendable: true,
        confirmations: 25533,
        amount: 0.06790578
    };

    let expected_tx_bytes : Bytes = "01000000011678e31558194155334e5ba7640082bb8f73ed31c0f29b7ede5a59015c09ad21010000006b483045022100b58aad4b24ec85975c3f3dee41aec6cb1ce0294e629e532cdc92fe922a67b0120220326cc8cf623f3ab13c278f44ea7f8035578c52670fe63abb349353c283d9df1a012103c6a78589e18b482aea046975e6d0acbdea7bf7dbf04d9d5bd67fda917815e3edffffffff01ca9967000000000017a914022a9aa2d065d7dbbe3661cc01bb78f4c0eea9838700000000".into();

    let tx_bytes = serialize(&p2sh_tx(
        &unspent,
        &key_pair0,
        &"630438d5075bb17582012088a9142ddc0d0532e538f8c79ac1f0b1adba91340b1ca9882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac6782012088a9148ec037062dcee8a324fe16d5ebf67967e1361911882103c6a78589e18b482aea046975e6d0acbdea7bf7dbf04d9d5bd67fda917815e3edac68".into(),
        0.06789578
    ));

    assert_eq!(expected_tx_bytes, tx_bytes);
}

#[test]
fn test_create_alice_payment_spend_tx() {
    // etomic tx: d7087d3f3ee5f14657178cb7475f8ac3ae0f882a4c89213dc6d522faeb97aedf
    let seed = env::var("SEED1").unwrap();
    let key_pair0 = key_pair_from_seed(seed.as_bytes());

    let priv_1 = H256::from_str(&env::var("PRIV2").unwrap()).unwrap();

    let private = Private {
        network: Network::Mainnet,
        secret: priv_1,
        compressed: true,
    };

    let key_pair1 = KeyPair::from_private(private).unwrap();

    let tx_out = OutPoint {
        hash: H256::from_reversed_str("8a6762514cd7813a458fe7cc7e1a0093e1fa19b174879ea5f74ff87c56cfe7eb"),
        index: 0
    };

    let expected_tx_bytes : Bytes = "0100000001ebe7cf567cf84ff7a59e8774b119fae193001a7ecce78f453a81d74c5162678a00000000d90047304402207f6d2eea32b6dff377cc9e23a54f3001d8bb806b89d4d52f93fa5b6f370de47d02207d108fd208d3a7e35c6517c7e1b71316a9574503e59496a7a70fb2f38623439c0147304402206fdcf11ecf7b65ce330373d32e247baa73a73f69a0004e4232a891b973b6af5d022065d4d2afd69ed58fc526f21b6699addda83be110df2918b0ffe9ca334342cf5d0147522102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f321030c487c2249a7925045c0fbb4d49fdc6d235ab693df83ea1c60d977c4a397248a52aeffffffff011c342600000000001976a91405aab5342166f8594baf17a7d9bef5d56744332788ac00000000".into();

    let output = TransactionOutput {
        value: 2503708,
        script_pubkey: "76a91405aab5342166f8594baf17a7d9bef5d56744332788ac".into()
    };

    let tx_bytes = serialize(&alice_payment_spend_tx(tx_out, output, &key_pair0, &key_pair1));

    assert_eq!(expected_tx_bytes, tx_bytes);
}

#[test]
fn test_extract_bob_priv_n() {
    let deposit_spend_script: Script = Bytes::from_str(&format!("483045022100efd0659a274566dfaf7e6e49c126a02174242e4db62177b651d65ee54888f41b02200fda45508b0117fea026d427de40cb243bf54f7b5f7cb670c35da160b0dca4a60120{}004c866304029bfa5ab17582012088a91459772344029b42e8bbd104dedc3bcebef12e46b0882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac6782012088a91459772344029b42e8bbd104dedc3bcebef12e46b0882102031d4256c4bc9f99ac88bf3dba21773132281f65f9bf23a59928bce08961e2f3ac68", env::var("PRIV2").unwrap())).unwrap().into();

    let private = Private {
        network: Network::Mainnet,
        secret: H256::from_str(&env::var("PRIV2").unwrap()).unwrap(),
        compressed: true,
    };

    let expected = KeyPair::from_private(private).unwrap();

    let actual = extract_bob_priv_n(&deposit_spend_script);
    assert_eq!(actual, expected);
}
