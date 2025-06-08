// Copyright (c) 2025 Max Wickham
// SPDX-License-Identifier: MIT
// See the MIT License for details: https://opensource.org/licenses/MIT

use std::sync::Arc;

use alloy::providers::fillers::{
    BlobGasFiller,
    ChainIdFiller,
    FillProvider,
    GasFiller,
    JoinFill,
    NonceFiller,
    WalletFiller,
};
use alloy::providers::{ Identity, RootProvider };
use alloy::transports::http::{ Client, Http };
use alloy::sol;
use alloy::transports::layers::RetryBackoffService;
use alloy::network::{ Ethereum, EthereumWallet };

use IIgloo::IIglooInstance;

// prettier-ignore
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    #[derive(Debug)]
    IIgloo,
    "abi/IIgloo.json"
}

pub type Contract = IIglooInstance<
    RetryBackoffService<Http<Client>>,
    Arc<
        FillProvider<
            JoinFill<
                JoinFill<
                    Identity,
                    JoinFill<
                        GasFiller,
                        JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>
                    >
                >,
                WalletFiller<EthereumWallet>
            >,
            RootProvider<RetryBackoffService<Http<Client>>>,
            RetryBackoffService<Http<Client>>,
            Ethereum
        >
    >
>;
