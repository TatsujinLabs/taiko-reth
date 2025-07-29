use std::{cmp::min, fmt::Debug, sync::Arc};

use alloy_consensus::{BlockHeader as AlloyBlockHeader, EMPTY_OMMER_ROOT_HASH};
use alloy_hardforks::EthereumHardforks;
use reth::{
    beacon_consensus::validate_block_post_execution,
    chainspec::EthChainSpec,
    consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator},
    consensus_common::validation::{
        validate_against_parent_hash_number, validate_body_against_header,
        validate_header_base_fee, validate_header_extra_data, validate_header_gas,
    },
    primitives::SealedBlock,
};
use reth_node_api::NodePrimitives;
use reth_primitives_traits::{Block, BlockHeader, GotExpected, RecoveredBlock, SealedHeader};
use reth_provider::{BlockExecutionResult, BlockReader};

use crate::chainspec::{hardfork::TaikoHardforks, spec::TaikoChainSpec};

const ELASTICITY_MULTIPLIER: u64 = 2;

/// Taiko consensus implementation.
///
/// Provides basic checks as outlined in the execution specs.
#[derive(Debug, Clone)]
pub struct TaikoBeaconConsensus<R: BlockReader> {
    chain_spec: Arc<TaikoChainSpec>,
    block_reader: R,
}

impl<R: BlockReader> TaikoBeaconConsensus<R> {
    /// Create a new instance of [`TaikoBeaconConsensus`]
    pub fn new(chain_spec: Arc<TaikoChainSpec>, block_reader: R) -> Self {
        Self {
            chain_spec,
            block_reader,
        }
    }
}

impl<N, R> FullConsensus<N> for TaikoBeaconConsensus<R>
where
    N: NodePrimitives,
    R: BlockReader + Debug,
{
    /// Validate a block with regard to execution results:
    ///
    /// - Compares the receipts root in the block header to the block body
    /// - Compares the gas used in the block header to the actual gas usage after execution
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
    ) -> Result<(), ConsensusError> {
        validate_block_post_execution(block, &self.chain_spec, &result.receipts, &result.requests)
    }
}

impl<B: Block, R> Consensus<B> for TaikoBeaconConsensus<R>
where
    R: BlockReader + Debug,
{
    /// The error type related to consensus.
    type Error = ConsensusError;

    /// Ensures the block response data matches the header.
    ///
    /// This ensures the body response items match the header's hashes:
    ///   - ommer hash
    ///   - transaction root
    ///   - withdrawals root
    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        validate_body_against_header(body, header.header())
    }

    /// Validate a block without regard for state:
    ///
    /// - Compares the ommer hash in the block header to the block body
    /// - Compares the transactions root in the block header to the block body
    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        // In Taiko network, ommer hash is always empty.
        if block.ommers_hash() != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::BodyOmmersHashDiff(
                GotExpected { got: block.ommers_hash(), expected: block.ommers_hash() }.into(),
            ));
        }

        Ok(())
    }
}

impl<H, R> HeaderValidator<H> for TaikoBeaconConsensus<R>
where
    H: BlockHeader,
    R: BlockReader + Debug,
{
    /// Validate if header is correct and follows consensus specification.
    ///
    /// This is called on standalone header to check if all hashes are correct.
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        let header = header.header();

        if !header.difficulty().is_zero() {
            return Err(ConsensusError::TheMergeDifficultyIsNotZero);
        }

        if !header.nonce().is_some_and(|nonce| nonce.is_zero()) {
            return Err(ConsensusError::TheMergeNonceIsNotZero);
        }

        if header.ommers_hash() != EMPTY_OMMER_ROOT_HASH {
            return Err(ConsensusError::TheMergeOmmerRootIsNotEmpty);
        }

        validate_header_extra_data(header)?;
        validate_header_gas(header)?;
        validate_header_base_fee(header, &self.chain_spec)
    }

    /// Validate that the header information regarding parent are correct.
    ///
    /// In Taiko network, we only need to validate block number, and timestamp,
    /// and we allow a block's timestamp to be equal to its parent's timestamp. Basefee, and
    /// gas limit checks are not needed.
    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        validate_against_parent_hash_number(header.header(), parent)?;

        if header.timestamp() < parent.timestamp() {
            return Err(ConsensusError::TimestampIsInPast {
                parent_timestamp: parent.timestamp(),
                timestamp: header.timestamp(),
            });
        }

        validate_against_parent_eip4936_base_fee(
            header.header(),
            parent.header(),
            &self.chain_spec,
            &self.block_reader,
        )?;

        Ok(())
    }
}

/// Validates the base fee against the parent.
#[inline]
pub fn validate_against_parent_eip4936_base_fee<
    ChainSpec: EthChainSpec + EthereumHardforks + TaikoHardforks,
    H: BlockHeader,
    R: BlockReader + Debug,
>(
    header: &H,
    parent: &H,
    chain_spec: &ChainSpec,
    block_reader: R,
) -> Result<(), ConsensusError> {
    let base_fee = header
        .base_fee_per_gas()
        .ok_or(ConsensusError::BaseFeeMissing)?;

    if chain_spec.is_shasta_active_at_block(header.number()) {
        let parent_block_time = if parent.number() > 2 {
            let ancestor = block_reader
                .block_by_hash(parent.parent_hash())
                .map_err(|_| ConsensusError::ParentUnknown {
                    hash: parent.parent_hash(),
                })?
                .ok_or(ConsensusError::ParentUnknown {
                    hash: parent.parent_hash(),
                })?;
            ancestor.header().timestamp() - parent.timestamp()
        } else {
            12 // TODO: determine the default value
        };

        let expected = calculate_next_block_eip4936_base_fee(header, parent, parent_block_time);
        if expected != base_fee {
            return Err(ConsensusError::BaseFeeDiff(GotExpected {
                expected,
                got: base_fee,
            }));
        }
    }

    Ok(())
}

/// Calculate the base fee for the next block based on the EIP-4936 specification.
pub fn calculate_next_block_eip4936_base_fee<H: BlockHeader>(
    _header: &H,
    parent: &H,
    parent_block_time: u64,
) -> u64 {
    // TODO: decode the gas issued per second from `header.extradata`.
    // Calculate the target gas by dividing the gas limit by the elasticity multiplier.
    let gas_target = parent.gas_limit() / ELASTICITY_MULTIPLIER as u64;
    let gas_target_adjusted = min(
        gas_target * parent_block_time / gas_target,
        parent.gas_limit() * 95 / 100,
    );
    let parent_base_fee = parent.base_fee_per_gas().unwrap();

    match parent.gas_used().cmp(&gas_target) {
        // If the gas used in the current block is equal to the gas target, the base fee remains the
        // same (no increase).
        core::cmp::Ordering::Equal => parent_base_fee,
        // If the gas used in the current block is greater than the gas target, calculate a new
        // increased base fee.
        core::cmp::Ordering::Greater => {
            // Calculate the increase in base fee based on the formula defined by EIP-4936.
            parent_base_fee
                + (core::cmp::max(
                    // Ensure a minimum increase of 1.
                    1,
                    parent_base_fee as u128 * (parent.gas_used() - gas_target_adjusted) as u128
                        / (gas_target as u128 * 8),
                ) as u64)
        }
        // If the gas used in the current block is less than the gas target, calculate a new
        // decreased base fee.
        core::cmp::Ordering::Less => {
            // Calculate the decrease in base fee based on the formula defined by EIP-1559.
            parent_base_fee.saturating_sub(
                (parent_base_fee as u128 * (gas_target_adjusted - parent.gas_used()) as u128
                    / (gas_target as u128 * 8)) as u64,
            )
        }
 }

#[cfg(test)]
mod test {
    use alloy_consensus::{Header, constants::MAXIMUM_EXTRA_DATA_SIZE};
    use alloy_primitives::{B64, B256, Bytes, U64, U256};
    use reth_cli::chainspec::ChainSpecParser;

    use crate::chainspec::parser::TaikoChainSpecParser;

    use super::*;

    #[test]
    fn test_validate_against_parent_eip4936_base_fee() {
        let parent_header = &Header::default();
        let mut header = parent_header.clone();
        header.parent_hash = parent_header.hash_slow();
        header.number = parent_header.number + 1;

        assert!(
            validate_against_parent_eip4936_base_fee(
                &header,
                parent_header,
                &Arc::new(TaikoChainSpec::default())
            )
            .is_err()
        );

        header.base_fee_per_gas = Some(U64::random().to::<u64>());
        assert!(
            validate_against_parent_eip4936_base_fee(
                &header,
                parent_header,
                &Arc::new(TaikoChainSpec::default())
            )
            .is_ok()
        );
    }

    #[test]
    fn test_validate_header() {
        let consensus = TaikoBeaconConsensus::new(TaikoChainSpecParser::parse("mainnet").unwrap());

        let mut header = Header::default();
        header.difficulty = U256::random().saturating_add(U256::from(1));
        assert_eq!(
            consensus.validate_header(&SealedHeader::new(header.clone(), header.hash_slow())),
            Err(ConsensusError::TheMergeDifficultyIsNotZero)
        );
        header.difficulty = U256::ZERO;

        header.nonce = B64::random();
        assert_eq!(
            consensus.validate_header(&SealedHeader::new(header.clone(), header.hash_slow())),
            Err(ConsensusError::TheMergeNonceIsNotZero)
        );
        header.nonce = B64::ZERO;

        header.ommers_hash = B256::random();
        assert_eq!(
            consensus.validate_header(&SealedHeader::new(header.clone(), header.hash_slow())),
            Err(ConsensusError::TheMergeOmmerRootIsNotEmpty)
        );
        header.ommers_hash = EMPTY_OMMER_ROOT_HASH;

        header.extra_data = Bytes::from(vec![0; MAXIMUM_EXTRA_DATA_SIZE + 1]);
        assert_eq!(
            consensus.validate_header(&SealedHeader::new(header.clone(), header.hash_slow())),
            Err(ConsensusError::ExtraDataExceedsMax { len: MAXIMUM_EXTRA_DATA_SIZE + 1 })
        );
        header.extra_data = Bytes::from(vec![0; MAXIMUM_EXTRA_DATA_SIZE]);

        header.gas_used = header.gas_limit + 1;
        assert_eq!(
            consensus.validate_header(&SealedHeader::new(header.clone(), header.hash_slow())),
            Err(ConsensusError::HeaderGasUsedExceedsGasLimit {
                gas_used: header.gas_used,
                gas_limit: header.gas_limit,
            })
        );
        header.gas_used = header.gas_limit;

        header.number = 1;
        header.base_fee_per_gas = None;
        assert_eq!(
            consensus.validate_header(&SealedHeader::new(header.clone(), header.hash_slow())),
            Err(ConsensusError::BaseFeeMissing)
        );
    }

    #[test]
    fn test_validate_header_against_parent() {
        let consensus = TaikoBeaconConsensus::new(TaikoChainSpecParser::parse("mainnet").unwrap());

        let mut parent = Header::default();
        let mut header = parent.clone();
        header.number = parent.number + 1;
        header.parent_hash = B256::random();
        assert_eq!(
            consensus.validate_header_against_parent(
                &SealedHeader::new(header.clone(), header.hash_slow()),
                &SealedHeader::new(parent.clone(), parent.hash_slow())
            ),
            Err(ConsensusError::ParentHashMismatch(
                GotExpected { got: header.parent_hash, expected: parent.hash_slow() }.into()
            ))
        );

        parent.timestamp = U64::random().to::<u64>();
        header.parent_hash = parent.hash_slow();
        header.timestamp = parent.timestamp;
        header.base_fee_per_gas = Some(U64::random().to::<u64>());
        assert!(
            consensus
                .validate_header_against_parent(
                    &SealedHeader::new(header.clone(), header.hash_slow()),
                    &SealedHeader::new(parent.clone(), parent.hash_slow()),
                )
                .is_ok()
        );

        header.timestamp = parent.timestamp - 1;
        assert_eq!(
            consensus.validate_header_against_parent(
                &SealedHeader::new(header.clone(), header.hash_slow()),
                &SealedHeader::new(parent.clone(), parent.hash_slow()),
            ),
            Err(ConsensusError::TimestampIsInPast {
                parent_timestamp: parent.timestamp,
                timestamp: header.timestamp,
            })
        );

        header.timestamp = parent.timestamp + 1;
        header.base_fee_per_gas = None;
        assert_eq!(
            consensus.validate_header_against_parent(
                &SealedHeader::new(header.clone(), header.hash_slow()),
                &SealedHeader::new(parent.clone(), parent.hash_slow()),
            ),
            Err(ConsensusError::BaseFeeMissing)
        );
    }
}
