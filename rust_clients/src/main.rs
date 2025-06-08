// Copyright (c) 2025 Max Wickham
// SPDX-License-Identifier: MIT
// See the MIT License for details: https://opensource.org/licenses/MIT

use std::path::PathBuf;
use std::sync::Arc;

use alloy::primitives::Uint;
use alloy::providers::fillers::{
    BlobGasFiller,
    ChainIdFiller,
    FillProvider,
    GasFiller,
    JoinFill,
    NonceFiller,
    WalletFiller,
};
use alloy::providers::{ Identity, Provider, ProviderBuilder, RootProvider };
use alloy::rpc::client::ClientBuilder;
use alloy::primitives::Address;
use alloy::transports::http::{ Client, Http };
use alloy::transports::layers::{ RetryBackoffLayer, RetryBackoffService };
use alloy::signers::local::LocalSigner;
use alloy::network::{ Ethereum, EthereumWallet };
use eyre::{ Result, WrapErr };
use clap::{Arg, ArgMatches, Command };
use log::info;

use contract::IIgloo;
use ceremony::ParticipantHandler;

mod ceremony;
mod utils;
mod contract;

type SigningProvider = Arc<
    FillProvider<
        JoinFill<
            JoinFill<
                Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>
            >,
            WalletFiller<EthereumWallet>
        >,
        RootProvider<RetryBackoffService<Http<Client>>>,
        RetryBackoffService<Http<Client>>,
        Ethereum
    >
>;

type NonSigningProvider = Arc<
    FillProvider<
        JoinFill<
            Identity,
            JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>
        >,
        RootProvider<RetryBackoffService<Http<Client>>>,
        RetryBackoffService<Http<Client>>,
        Ethereum
    >
>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // -------------------- Parse Args --------------------

    let matches = Command::new("igloo")
        .version("0.0.1")
        .author("Max Wickham")
        .about("A simple Client to interact with the \"Igloo\" frost key generation contract")
        .subcommand(
            Command::new("ceremony")
                .about("Run the Frost key generation ceremony on the Igloo contract")
                .arg(
                    Arg::new("igloo_address").required(true).value_parser(clap::value_parser!(String))
                )
                .arg(
                    Arg::new("rpc_url")
                        .long("rpc-url")
                        .help("Ethereum RPC URL")
                        .env("ETH_RPC_URL")
                        .required(true)
                        .value_parser(clap::value_parser!(String))
                )
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .help("Path to keystore file")
                        .env("KEYSTORE")
                        .required(true)
                        .requires("password")
                        .value_parser(clap::value_parser!(String))
                )
                .arg(
                    Arg::new("password")
                        .long("password")
                        .help("Password for keystore file")
                        .env("KEYSTORE_PASSWORD")
                        .required(true)
                        .requires("keystore")
                        .value_parser(clap::value_parser!(String))
                )
        )
        .subcommand(
            Command::new("state")
                .about("Query the state of the Igloo contract")
                .arg(
                    Arg::new("igloo_address").required(true).value_parser(clap::value_parser!(String))
                )
                .arg(
                    Arg::new("rpc_url")
                        .long("rpc-url")
                        .help("Ethereum RPC URL")
                        .env("ETH_RPC_URL")
                        .required(true)
                        .value_parser(clap::value_parser!(String))
                )
        )
        .subcommand(
            Command::new("deprecate")
                .about("Deprecate the Igloo contract")
                .arg(
                    Arg::new("igloo_address").required(true).value_parser(clap::value_parser!(String))
                )
                .arg(
                    Arg::new("rpc_url")
                        .long("rpc-url")
                        .help("Ethereum RPC URL")
                        .env("ETH_RPC_URL")
                        .required(true)
                        .value_parser(clap::value_parser!(String))
                )
                .arg(
                    Arg::new("keystore")
                        .long("keystore")
                        .help("Path to keystore file")
                        .env("KEYSTORE")
                        .required(true)
                        .requires("password")
                        .value_parser(clap::value_parser!(String))
                )
                .arg(
                    Arg::new("password")
                        .long("password")
                        .help("Password for keystore file")
                        .env("KEYSTORE_PASSWORD")
                        .required(true)
                        .requires("keystore")
                        .value_parser(clap::value_parser!(String))
                )
        )
        .get_matches();

    // -------------------- Setup Logger --------------------

    env_logger::init();

    // -------------------- Handle Subcommands --------------------

    match matches.subcommand() {
        Some(("ceremony", sub_matches)) => {
            let eth_address = sub_matches
                .get_one::<String>("igloo_address")
                .ok_or("Missing or invalid eth_address argument")?;

            let (provider, signer, private_key) = get_signing_provider(sub_matches)?;
            let chain_id = provider.get_chain_id().await?;

            info!("Igloo Address: {}", eth_address);
            info!("Participant Address: {}", signer.default_signer().address());

            // -------------------- Load Contract --------------------

            let contract = IIgloo::new(eth_address.parse::<Address>()?, provider.clone());

            // -------------------- Gen Participant Variables -------------------------

            let participant_handler = ParticipantHandler::new(
                signer,
                contract.clone(),
                chain_id,
                &private_key
            ).await?;

            // -------------------- Run the Ceremony Loop --------------------

            participant_handler.run_ceremony().await
        }
        Some(("state", sub_matches)) => {
            let eth_address = sub_matches
                .get_one::<String>("igloo_address")
                .ok_or("Missing or invalid eth_address argument")?;

            let provider = get_provider(sub_matches)?;

            let contract = IIgloo::new(eth_address.parse::<Address>()?, provider.clone());

            let state = contract
                .state_1()
                .call().await
                .wrap_err_with(||
                    format!("Failed to query state for contract at {}", eth_address)
                )?._0;

            match state {
                0 => println!("State: Round1"),
                1 => println!("State: Round2"),
                2 => println!("State: Round3"),
                3 => println!("State: Active"),
                4 => println!("State: Deprecated"),
                5 => println!("State: Failed"),
                _ => println!("Unknown state: {}", state),
            }

            let participants = contract
                .participants()
                .call().await
                .wrap_err_with(||
                    format!("Failed to query participants for contract at {}", eth_address)
                )?._0;
            println!("Participants: {:?}", participants);

            let threshold = contract
                .threshold()
                .call().await
                .wrap_err_with(||
                    format!("Failed to query threshold for contract at {}", eth_address)
                )?._0;

            println!("Threshold: {:?}", threshold);
            
            if state == 3 {
                let public_key = contract
                .publicKey()
                .call().await
                .wrap_err_with(||
                    format!("Failed to query public key for contract at {}", eth_address)
                )?._0;
                println!("Public Key: ({:?},{:?})", public_key.x, public_key.y);
            }

            Ok(())
        }
        Some(("deprecate", sub_matches)) => {
            let eth_address = sub_matches
                .get_one::<String>("igloo_address")
                .ok_or("Missing or invalid eth_address argument")?;

            let (provider, signer, _) = get_signing_provider(sub_matches)?;

            info!("Igloo Address: {}", eth_address);
            info!("Participant Address: {}", signer.default_signer().address());

            // -------------------- Load Contract --------------------

            let contract = IIgloo::new(eth_address.parse::<Address>()?, provider.clone());

            // -------------------- Deprecate the Contract --------------------

            let state = contract
                .state_1()
                .call().await
                .wrap_err_with(||
                    format!("Failed to query state for contract at {}", eth_address)
                )?._0;

            if state != 3 {
                // Only allow deprecation if the contract is in the Active state
                return Err("Key must be active to deprecate".into());
            }

            let index = contract
                .index(signer.default_signer().address())
                .call().await
                .wrap_err_with(||
                    format!(
                        "Failed to get participant index for address {}",
                        signer.default_signer().address()
                    )
                )?._0;
            contract.deprecateKey(index).send().await?.watch().await?;
            Ok(())
        }
        _ => {
            eprintln!("Invalid command. Use --help for usage information.");
            Ok(())
        }
    }
}

fn get_signing_provider(matches: &ArgMatches) -> Result<(SigningProvider, EthereumWallet, Uint<256, 4>),Box<dyn std::error::Error>> {
    let rpc_url = matches
        .get_one::<String>("rpc_url")
        .ok_or("Missing or invalid rpc_url argument")?;
    let keystore_path = matches
        .get_one::<String>("keystore")
        .ok_or("Missing or invalid keystore argument")?;
    let keystore_path = PathBuf::from(keystore_path);
    let password = matches
        .get_one::<String>("password")
        .ok_or("Missing or invalid password argument")?;

    let (signer, private_key) = {
        // Load the keystore and decrypt it
        let signer = LocalSigner::decrypt_keystore(&keystore_path, password).wrap_err_with(||
            "Failed to decrypt keystore".to_string()
        )?;
        let private_key_bytes = signer.to_bytes();
        let private_key = Uint::<256, 4>::from_be_bytes(private_key_bytes.into());
        (EthereumWallet::new(signer), private_key)
    };
    let client = ClientBuilder::default()
        .layer(RetryBackoffLayer::new(15, 200, 300))
        .http(rpc_url.parse()?);

    let provider = Arc::new(
        ProviderBuilder::new().with_recommended_fillers().wallet(signer.clone()).on_client(client)
    );
    Ok((provider, signer, private_key))
}

fn get_provider(matches: &ArgMatches) -> Result<NonSigningProvider, Box<dyn std::error::Error>> {
    let rpc_url = matches
        .get_one::<String>("rpc_url")
        .ok_or("Missing or invalid rpc_url argument")?;

    let client = ClientBuilder::default()
        .layer(RetryBackoffLayer::new(15, 200, 300))
        .http(rpc_url.parse()?);

    let provider = Arc::new(ProviderBuilder::new().with_recommended_fillers().on_client(client));

    Ok(provider)
}
