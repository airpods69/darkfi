/* This file is part of DarkFi (https://dark.fi)
 *
 * Copyright (C) 2020-2023 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use darkfi_sdk::{
    crypto::{
        pasta_prelude::*, pedersen_commitment_u64, poseidon_hash, ContractId, MerkleNode,
        PublicKey, DARK_TOKEN_ID,
    },
    dark_tree::DarkLeaf,
    db::{db_contains_key, db_get, db_lookup, db_set},
    error::{ContractError, ContractResult},
    merkle_add, msg,
    pasta::pallas,
    ContractCall,
};
use darkfi_serial::{deserialize, serialize, Encodable, WriteExt};

use crate::{
    error::MoneyError,
    model::{MoneyFeeParamsV1, MoneyFeeUpdateV1},
    MoneyFunction, MONEY_CONTRACT_COINS_TREE, MONEY_CONTRACT_COIN_MERKLE_TREE,
    MONEY_CONTRACT_COIN_ROOTS_TREE, MONEY_CONTRACT_INFO_TREE, MONEY_CONTRACT_LATEST_COIN_ROOT,
    MONEY_CONTRACT_NULLIFIERS_TREE, MONEY_CONTRACT_TOTAL_FEES_PAID, MONEY_CONTRACT_ZKAS_BURN_NS_V1,
    MONEY_CONTRACT_ZKAS_MINT_NS_V1,
};

/// `get_metadata` function for `Money::FeeV1`
pub(crate) fn money_fee_get_metadata_v1(
    _cid: ContractId,
    call_idx: u32,
    calls: Vec<DarkLeaf<ContractCall>>,
) -> Result<Vec<u8>, ContractError> {
    let self_ = &calls[call_idx as usize].data;
    let params: MoneyFeeParamsV1 = deserialize(&self_.data[1..])?;

    // Public inputs for the ZK proofs we have to verify
    let mut zk_public_inputs: Vec<(String, Vec<pallas::Base>)> = vec![];
    // Public keys for the transaction signatures we have to verify
    let mut signature_pubkeys: Vec<PublicKey> = vec![];

    // Grab the pedersen commitments and signature pubkeys from the
    // anonymous inputs
    for input in &params.inputs {
        let value_coords = input.value_commit.to_affine().coordinates().unwrap();
        let (sig_x, sig_y) = input.signature_public.xy();

        // It is very important that these are in the same order as the
        // `constrain_instance` calls in the zkas code.
        // Otherwise verification will fail.
        zk_public_inputs.push((
            MONEY_CONTRACT_ZKAS_BURN_NS_V1.to_string(),
            vec![
                input.nullifier.inner(),
                *value_coords.x(),
                *value_coords.y(),
                input.token_commit,
                input.merkle_root.inner(),
                input.user_data_enc,
                input.spend_hook,
                sig_x,
                sig_y,
            ],
        ));

        signature_pubkeys.push(input.signature_public);
    }

    // Grab the pedersen commitments from the anonymous outputs
    for output in &params.outputs {
        let value_coords = output.value_commit.to_affine().coordinates().unwrap();

        zk_public_inputs.push((
            MONEY_CONTRACT_ZKAS_MINT_NS_V1.to_string(),
            vec![output.coin.inner(), *value_coords.x(), *value_coords.y(), output.token_commit],
        ));
    }

    // Serialize everything gathered and return it
    let mut metadata = vec![];
    zk_public_inputs.encode(&mut metadata)?;
    signature_pubkeys.encode(&mut metadata)?;

    Ok(metadata)
}

/// `process_instruction` function for `Money::FeeV1`
pub(crate) fn money_fee_process_instruction_v1(
    cid: ContractId,
    call_idx: u32,
    calls: Vec<DarkLeaf<ContractCall>>,
) -> Result<Vec<u8>, ContractError> {
    let self_ = &calls[call_idx as usize];
    let params: MoneyFeeParamsV1 = deserialize(&self_.data.data[1..])?;

    // We need at least one input, but we shouldn't require any outputs.
    if params.inputs.is_empty() {
        msg!("[FeeV1] Error: No inputs in the call");
        return Err(MoneyError::FeeMissingInputs.into())
    }

    // Though, we should have some fee paid...
    /* XXX:
    if params.fee == 0 {
        msg!("[FeeV1] Error: Paid fee is 0");
        return Err(MoneyError::InsufficientFee.into())
    }
    */

    // Access the necessary databases where there is information to
    // validate this state transition.
    let info_db = db_lookup(cid, MONEY_CONTRACT_INFO_TREE)?;
    let coins_db = db_lookup(cid, MONEY_CONTRACT_COINS_TREE)?;
    let nullifiers_db = db_lookup(cid, MONEY_CONTRACT_NULLIFIERS_TREE)?;
    let coin_roots_db = db_lookup(cid, MONEY_CONTRACT_COIN_ROOTS_TREE)?;

    // Accumulator for the value commitments. We add inputs to it, and
    // subtract the outputs and the fee from it. For the commitments to
    // be valid, the accumulatior must be in its initial state after
    // performing the arithmetics.
    let mut valcom_total = pallas::Point::identity();

    // Fees can only be paid using the native token, so we'll compare
    // the token commitments with this one:
    let native_token_commit = poseidon_hash([DARK_TOKEN_ID.inner(), params.token_blind]);

    // ===================================
    // Perform the actual state transition
    // ===================================

    // For anonymous inputs, we must gather all the new nullifiers that
    // are introduced.
    let mut new_nullifiers = Vec::with_capacity(params.inputs.len());
    msg!("[FeeV1] Iterating over anonymous inputs");
    for (i, input) in params.inputs.iter().enumerate() {
        // Verify that the token commitment matches
        if input.token_commit != native_token_commit {
            msg!("[FeeV1] Error: Token commitment is not native token (input {})", i);
            return Err(MoneyError::TokenMismatch.into())
        }

        // The spend hook must be zero.
        if input.spend_hook != pallas::Base::ZERO {
            msg!("[FeeV1] Error: Input spend hook is nonzero (input {})", i);
            return Err(MoneyError::SpendHookNonZero.into())
        }

        // The Merkle root is used to know whether this is a coin that
        // existed in a previous state.
        if !db_contains_key(coin_roots_db, &serialize(&input.merkle_root))? {
            msg!("[FeeV1] Error: Merkle root not found in previous state (input {})", i);
            return Err(MoneyError::CoinMerkleRootNotFound.into())
        }

        // The nullifiers should not already exist. It is the double-spend protection.
        if new_nullifiers.contains(&input.nullifier) ||
            db_contains_key(nullifiers_db, &serialize(&input.nullifier))?
        {
            msg!("[FeeV1] Error: Duplicate nullifier found (input {})", i);
            return Err(MoneyError::DuplicateNullifier.into())
        }

        // Append this new nullifier to seen nullifiers, and accumulate the value commitment.
        new_nullifiers.push(input.nullifier);
        valcom_total += input.value_commit;
    }

    // Newly created coins for this call are in the outputs. Here we gather them,
    // and we also check that they haven't existed before.
    let mut new_coins = Vec::with_capacity(params.outputs.len());
    for (i, output) in params.outputs.iter().enumerate() {
        // Verify that the token commitment matches
        if output.token_commit != native_token_commit {
            msg!("[FeeV1] Error: Token commitment is not native token (output {})", i);
            return Err(MoneyError::TokenMismatch.into())
        }

        if new_coins.contains(&output.coin) || db_contains_key(coins_db, &serialize(&output.coin))?
        {
            msg!("[FeeV1] Error: Duplicate coin found (output {})", i);
            return Err(MoneyError::DuplicateCoin.into())
        }

        // Append this new coin to seen coins, and subtract the value commitment
        new_coins.push(output.coin);
        valcom_total -= output.value_commit;
    }

    // Now subtract the fee from the accumulator
    valcom_total -= pedersen_commitment_u64(params.fee, params.fee_value_blind);

    // If the accumulator is not back in its initial; state, that means there
    // is a value mismatch betweeen inputs and outputs.
    if valcom_total != pallas::Point::identity() {
        msg!("[FeeV1] Error: Value commitments do not result in identity");
        return Err(MoneyError::ValueMismatch.into())
    }

    // Accumulate the paid fee
    let mut paid_fee: u64 =
        deserialize(&db_get(info_db, MONEY_CONTRACT_TOTAL_FEES_PAID)?.unwrap())?;
    paid_fee += params.fee;

    // At this point the state transition has passed, so we create a state update.
    let update = MoneyFeeUpdateV1 { nullifiers: new_nullifiers, coins: new_coins, fee: paid_fee };
    let mut update_data = vec![];
    update_data.write_u8(MoneyFunction::FeeV1 as u8)?;
    update.encode(&mut update_data)?;
    // and return it
    Ok(update_data)
}

/// `process_update` function for `Money::FeeV1`
pub(crate) fn money_fee_process_update_v1(
    cid: ContractId,
    update: MoneyFeeUpdateV1,
) -> ContractResult {
    // Grab all necessary db handles for where we want to write
    let info_db = db_lookup(cid, MONEY_CONTRACT_INFO_TREE)?;
    let coins_db = db_lookup(cid, MONEY_CONTRACT_COINS_TREE)?;
    let nullifiers_db = db_lookup(cid, MONEY_CONTRACT_NULLIFIERS_TREE)?;
    let coin_roots_db = db_lookup(cid, MONEY_CONTRACT_COIN_ROOTS_TREE)?;

    msg!("[FeeV1] Adding new nullifiers to the set");
    for nullifier in &update.nullifiers {
        db_set(nullifiers_db, &serialize(nullifier), &[])?;
    }

    msg!("[FeeV1] Adding new coins to the set");
    for coin in &update.coins {
        db_set(coins_db, &serialize(coin), &[])?;
    }

    msg!("[FeeV1] Adding new coins to the Merkle tree");
    let coins: Vec<_> = update.coins.iter().map(|x| MerkleNode::from(x.inner())).collect();
    merkle_add(
        info_db,
        coin_roots_db,
        MONEY_CONTRACT_LATEST_COIN_ROOT,
        MONEY_CONTRACT_COIN_MERKLE_TREE,
        &coins,
    )?;

    db_set(info_db, MONEY_CONTRACT_TOTAL_FEES_PAID, &serialize(&update.fee))?;

    Ok(())
}