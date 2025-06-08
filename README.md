# Igloo

Igloo is an onchain implementation of the Frost signature key generation ceremony described in the paper "Frost: Flexible Round-Optimized Schnorr Threshold Signatures" by Ben-Sasson et al.

Igloo allows for the key generation ceremony required for Frost to be performed onchain. As well as simplifying client implementations by performing certain checks in the contract, performing the ceremony on chain allows for easy retrial of the ceremony state at any time in a decentralized manner. This is particularly useful for Frost signatures as in order to participate in a signing ceremony the client must be able to access the state of the key generation ceremony. 

## Frost Keys

Frost keys are are a threshold multisig implementation of Schnorr signatures. The keys are generated in a ceremony where each participant contributes a share of the key. The shares are then combined to form the final key. The key can then be used to sign messages and verify signatures.

Using the secrets shares created in the key generation ceremony, a threshold of the total participants can at any time create a single Schnorr signature to sign a message. The key benefit of this is that no matter how high the signing threshold the validation of the signature is always equal to a single schnorr signature validation. 

(It should be noted the complexity of the key generation ceremony is O(n^2) where n is the number of participants in the ceremony. This means that the ceremony can take a long time to complete if there are many participants. However, this is a one time cost.)

## Igloo CLI Tool

The igloo cli tool is a command line interface for interacting with the igloo contract. It is an extremely basic implementation and like the contract itself should not be used in production. 
The tool provides three main functionalities:
- Participate in the key generation ceremony
- Query the current state of the contract, (e.g. the current round, the participants, etc.)
- Deprecate the key.

The tool can be built by running `cargo build --release` in the `rust_client` directory. The binary will be located in `rust_client/target/release/igloo`.

## Contract Design

The Igloo contract makes heavy usage of the crysol library see [here](https://github.com/verklegarden/crysol) (credit to [MerklePlant](https://github.com/pmerkleplant) and the other authors) for elliptic curve operations. 

The contract is designed to perform exactly one key generation ceremony ever. If a new key is required a new contract must be deployed. 

The ceremony itself is performed in three rounds, more details on which can be found in the [Frost paper](https://eprint.iacr.org/2020/1261.pdf).

At any time any participant can deprecate the key, this will simply mark the key state as "deprecated". When signing messages participants should check the key state to ensure it is not deprecated before signing. This state could also be read by other on-chain contracts to ensure they are not using a deprecated key to validate signatures.

## Message Signing

Currently this repo provides no functionality for signing messages. In the future this may be added with a singing contract. However, it does not make much sense to perform the signing ceremony onchain.

## Deployment

Igloo used a proxy pattern for deployments to save on gas costs during deployment. In order to deploy a new instance a "factory" and "singleton" address must be provided. Existing addresses can be found in this README.


A forge script is provided to deploy a new proxy instance of the Igloo contract. Before running the script export the following environment variables:

- `RPC_URL`: The URL of the Ethereum RPC node to use for deployment.
- `KEYSTORE`: The path to the keystore file containing the private key of the deployer.
- `KEYSTORE_PASSWORD`: The password for the keystore file.
- `SENDER`: The address of the deployer. This is the address that will be used to deploy the contract.
- `FACTORY`: The address of the factory contract to use for deployment. This is the address of the `ProxyFactory` contract.
- `SINGLETON`: The address of the singleton contract to use for deployment. This is the address of the `Igloo` contract.
- `PARTICIPANTS`: The list of addresses of all participants in the key generation ceremony.
- `THRESHOLD`: The threshold number of participants required to sign a message (bust be greater than 0 and less than or equal to number of participants).
- `SALT`: A unique salt value used to derive the address of the new proxy contract. This can be any arbitrary value, but it must be unique for each deployment.

The following command can then be run to deploy a new instance:

```bash
forge script --keystore "$KEYSTORE" --password "$KEYSTORE_PASSWORD" --sender "$SENDER" --broadcast --rpc-url "$RPC_URL" --sig "$(cast calldata "deploy(address,address, string, address[] memory, uint)" "$SINGLETON" "$FACTORY" "$SALT" "$PARTICIPANTS" $THRESHOLD)" -vvv script/ProxyScript.s.sol:ProxyScript --broadcast
```

## Factory and Singleton Deployments.

Deployments of the factory and singleton contracts are provided below. These are the addresses that should be used for the `FACTORY` and `SINGLETON` environment variables when deploying a new instance of the Igloo contract.

TODO: Use Nicks methods for deployments.

### Version 0.0.1


```json
{
    "sep":{
        "chainId": 11155111,
        "factory": "0xddF333FE609612Edb4B569d104EBa98695F91f51",
        "singleton": "0x66FA886e8495519c233784623fEB9c3EF0908aC2"
    }
}
```
