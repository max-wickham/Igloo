// Copyright (c) 2025 Max Wickham
// SPDX-License-Identifier: MIT
// See the MIT License for details: https://opensource.org/licenses/MIT

use std::ops::Add;

use alloy::primitives::{ keccak256, Uint };
use alloy::primitives::Address;
use alloy::network::EthereumWallet;
use elliptic_curve::Field;
use eyre::Result;
use k256::{ ProjectivePoint, Scalar };
use rand_core::OsRng;
use log::info;

use crate::contract::{ Contract, IIgloo };
use crate::utils::{
    affine_to_point,
    point_to_projective,
    scalar_to_point,
    scalar_to_uint,
    u64_to_uint,
    uint_to_scalar,
};
use crate::utils::Q;

pub struct ParticipantHandler {
    contract: Contract,
    signer: EthereumWallet,
    pub coefficients: Vec<Scalar>,
    pub commitments: Vec<ProjectivePoint>,
    pub sigma: IIgloo::Sigma,
    pub channel_key_secret: Scalar,
    pub channel_key: ProjectivePoint,
}

impl ParticipantHandler {
    pub async fn new(
        signer: EthereumWallet,
        contract: Contract,
        chain_id: u64,
        private_key: &Uint<256, 4>
    ) -> Result<ParticipantHandler, Box<dyn std::error::Error>> {
        // Get contract state
        let threshold = contract.threshold().call().await?._0;
        let contract_address = contract.address();
        let participant = &signer.default_signer().address();

        let gen_uint = move |seed: Uint<256, 4>, string: &str| -> Uint<256, 4> {
            let mut input_bytes: Vec<u8> = chain_id.to_be_bytes().to_vec().clone();
            input_bytes.append(&mut threshold.to_be_bytes_vec());
            input_bytes.append(&mut contract_address.into_array().to_vec());
            input_bytes.append(&mut private_key.to_be_bytes_vec());
            input_bytes.append(&mut seed.to_be_bytes_vec());
            input_bytes.append(&mut string.as_bytes().to_vec());
            let hash = keccak256(input_bytes);

            Uint::<256, 4>::from_be_bytes(hash.into())
        };

        // Compute coefficients
        let mut coefficients = vec![];
        for i in 0..threshold.as_limbs()[0] as usize {
            let scalar = uint_to_scalar(
                gen_uint(u64_to_uint(i as u64), "Igloo::coefficients")
            );

            coefficients.push(scalar);
        }

        // Compute commitments
        let mut commitments = vec![];
        for coefficient in coefficients.iter() {
            commitments.push(scalar_to_point(*coefficient));
        }

        // Compute Sigma
        let k = uint_to_scalar(gen_uint(Uint::<256, 4>::ZERO, "Igloo::K"));
        // R = k * G
        let r = scalar_to_point(k);
        let r = affine_to_point(r.to_affine());
        let phi = commitments[0];
        let a = coefficients[0];
        assert!(scalar_to_point(a).eq_affine(&phi.to_affine()).unwrap_u8() == 1);

        let phi = affine_to_point(phi.to_affine());
        let challenge = contract
            .participantChallenge(*participant, phi.clone(), r.clone())
            .call().await?._0;
        let challenge = uint_to_scalar(challenge);

        // mu = k + a0 * c
        let mu = k.add(&a.mul(&challenge));
        let mu: Uint<256, 4> = scalar_to_uint(mu);
        let sigma = IIgloo::Sigma {
            R: r.clone(),
            mu,
        };

        // R + c_i * A_i_0 = mu * G
        assert!(
            point_to_projective(r.clone()) + point_to_projective(phi.clone()) * challenge ==
                ProjectivePoint::GENERATOR * uint_to_scalar(mu)
        );

        // Compute channel key
        let channel_key_secret = uint_to_scalar(
            gen_uint(Uint::<256, 4>::ZERO, "Igloo::ChannelKeySecret")
        );
        let channel_key = scalar_to_point(channel_key_secret);

        Ok(ParticipantHandler {
            signer: signer.clone(),
            contract: contract.clone(),
            coefficients,
            commitments,
            sigma,
            channel_key_secret,
            channel_key,
        })
    }

    pub async fn run_ceremony(&self) -> Result<(), Box<dyn std::error::Error>> {
        let participants = self.contract.participants().call().await?._0;
        let participant: Address = self.signer.default_signer().address();
        let index = self.contract.index(participant).call().await?._0;
        let threshold = self.contract.threshold().call().await?._0;

        info!("Running ceremony with the following parameters:");
        info!("Contract Address: {:?}", self.contract.address());
        info!("Participants: {:?}", participants);
        info!("Participant Address: {:?}", participant);
        info!("Participant Index: {:?}", index);
        info!("Threshold: {:?}", threshold);

        loop {
            let state = self.contract.state_1().call().await?._0;
            match state {
                0 => {
                    // Round 1
                    info!("Global State: {} - Round 1", state);
                }
                1 => {
                    // Round 2
                    info!("Global State: {} - Round 2", state);
                }
                2 => {
                    // Round 3
                    info!("Global State: {} - Round 3", state);
                }
                3 => {
                    // Active
                    info!("Global State: {} - Active", state);
                    break;
                }
                4 => {
                    // Deprecated
                    info!("Global State: {} - Deprecated", state);
                    break;
                }
                5 => {
                    // Failed
                    info!("Global State: {} - Failed", state);
                    break;
                }
                _ => {
                    info!("Global State: {} - In progress", state);
                }
            }

            let participant_state = self.contract.state_0(index).call().await?._0;
            match participant_state {
                0 => {
                    // Round 1
                    info!("Participant state: {} - Round 1", participant_state);

                    self.process_round_1(index).await?;

                    info!("Processed Round 1");
                }
                1 => {
                    // Pending Round 2
                    info!("Participant state: {} - Pending Round 2", participant_state);
                }
                2 => {
                    // Round 2
                    info!("Participant state: {} - Round 2", participant_state);

                    self.process_round_2(&participants, index).await?;

                    info!("Processed Round 2");
                }
                3 => {
                    // Pending Round 3
                    info!("Participant state: {} - Pending Round 3", participant_state);
                }
                4 => {
                    // Round 3
                    info!("Participant state: {} - Round 3", participant_state);

                    self.process_round_3(index).await?;

                    info!("Processed Round 3");
                }
                5 => {
                    // Pending Active
                    info!("Participant state: {} - Pending Active", participant_state);
                }
                6 => {
                    // Active
                    info!("Participant state: {} - Active", participant_state);
                    break;
                }
                _ => {
                    info!("Participant state: {} - In progress", participant_state);
                }
            }

            // Wait for a second before checking again
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }

        Ok(())
    }


    async fn process_round_1(&self, index: Uint<256, 4>) -> Result<(), Box<dyn std::error::Error>> {
        let mut commitments_point = vec![];
        let commitments = self.commitments.clone();
        for point in commitments.iter() {
            commitments_point.push(affine_to_point(point.to_affine()));
        }
        self.contract
            .shareCommitments(
                index,
                commitments_point,
                self.sigma.clone(),
                affine_to_point(self.channel_key.clone().to_affine())
            )
            .send().await?
            .watch().await?;
        Ok(())
    }
    
    async fn process_round_2(
        &self,
        participants: &Vec<Address>,
        index: Uint<256, 4>
    ) ->  Result<(), Box<dyn std::error::Error>> {
        let channel_keys = Some(self.contract.channelKeys().call().await?._0);
        let mut results = vec![];
        for mut i in 0..participants.len() as usize {
            // Evaluate polynomial on each of the participant indexes.
            // Note the index here is 1 greater than the index in the contract.
            i += 1;
            let i = scalar_to_uint(Scalar::from(i as u64));
            let coefficients = self.coefficients.clone();
            // Iterate through coefficients
            let mut result = Uint::<256, 4>::ZERO;
            let mut sum = ProjectivePoint::IDENTITY;
            for j in 0..coefficients.len() {
                // Evaluate polynomial
                let coeff = scalar_to_uint(coefficients[j]);
                let commitment = self.commitments[j];

                let exponent = u64_to_uint(j as u64);

                let val = coeff.mul_mod(i.pow_mod(exponent, *Q), *Q);
                result = result.add_mod(val, *Q);

                let val = commitment * uint_to_scalar(i.pow_mod(exponent, *Q));
                sum += val;
            }
            assert!(
                sum == scalar_to_point(uint_to_scalar(result))
            );
            results.push(result);
        }
        let mut encrypted_outputs = vec![];
        for i in 0..participants.len() as usize {
            let p_channel_key = channel_keys.as_ref().unwrap()[i].clone();
            let p_channel_key = point_to_projective(p_channel_key);
            // R = k * G
            let m = scalar_to_point(Scalar::random(&mut OsRng));
            let k = Scalar::random(&mut OsRng);
            let c1 = scalar_to_point(k);
            let c2 = m + p_channel_key * k;
            let mx = affine_to_point(m.to_affine()).x % *Q;
            let result = results[i];

            // (M.x + output) % q
            let e_output = mx.add_mod(result, *Q);
            let encrypted_output = IIgloo::FunctionOutput {
                eOutput: e_output,
                C1: affine_to_point(c1.to_affine()),
                C2: affine_to_point(c2.to_affine()),
            };
            encrypted_outputs.push(encrypted_output);
        }
        self.contract.shareFunctionOutputs(index, encrypted_outputs).send().await?.watch().await?;
        Ok(())
    }

    async fn process_round_3(&self, index: Uint<256, 4>) ->  Result<(), Box<dyn std::error::Error>>  {
        let function_outputs = self.contract.functionOutputs(index).call().await?._0;
        let mut decrypted_function_outputs = vec![];
        for output in function_outputs.iter() {
            let c1 = point_to_projective(output.C1.clone());
            let c2 = point_to_projective(output.C2.clone());
            let m = c2 - c1 * self.channel_key_secret;
            let mx = affine_to_point(m.to_affine()).x % *Q;

            let d_output = output.eOutput.add_mod(*Q - mx, *Q);
            decrypted_function_outputs.push(d_output);
        }
        let commitments = self.contract.commitments().call().await?._0;
        for (i, output) in decrypted_function_outputs.iter().enumerate() {
            let participant_commitments = commitments[i].clone();
            // Iterate through the commitments, and compute commitment * index ^ i
            let mut sum = ProjectivePoint::IDENTITY;
            for (j, commitment) in participant_commitments.iter().enumerate() {
                let commitment = point_to_projective(commitment.clone());
                let exponent = u64_to_uint(j as u64);
                let val =
                    commitment * uint_to_scalar((index + u64_to_uint(1)).pow_mod(exponent, *Q));
                sum += val;
            }
            let expected_sum = scalar_to_point(uint_to_scalar(*output));
            assert!(
                affine_to_point(expected_sum.to_affine()).x == affine_to_point(sum.to_affine()).x
            );
        }
        self.contract.validateFunctionOutputs(index).send().await?.watch().await?;
        Ok(())
    }

}
