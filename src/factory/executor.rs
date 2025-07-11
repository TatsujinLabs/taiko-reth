use alloy_consensus::{Transaction, TxReceipt};
use alloy_eips::{Encodable2718, eip7685::Requests};
use alloy_evm::{
    Database, FromRecoveredTx, FromTxWithEncoded,
    eth::{receipt_builder::ReceiptBuilder, spec::EthExecutorSpec},
};
use alloy_primitives::Address;
use reth::{
    primitives::Log,
    revm::{
        State,
        context::result::{ExecutionResult, ResultAndState},
    },
};
use reth_evm::{
    Evm, OnStateHook,
    block::{
        BlockExecutionError, BlockExecutor, BlockValidationError, CommitChanges, ExecutableTx,
        StateChangeSource, SystemCaller,
    },
    eth::receipt_builder::ReceiptBuilderCtx,
};
use reth_provider::BlockExecutionResult;
use revm_database_interface::DatabaseCommit;

use crate::factory::{alloy::TAIKO_GOLDEN_TOUCH_ADDRESS, block::TaikoBlockExecutionCtx};

/// Block executor for Taiko network.
pub struct TaikoBlockExecutor<'a, Evm, Spec, R: ReceiptBuilder> {
    /// Reference to the specification object.
    spec: Spec,

    /// Context for block execution.
    pub ctx: TaikoBlockExecutionCtx<'a>,
    /// Inner EVM.
    evm: Evm,
    /// Utility to call system smart contracts.
    system_caller: SystemCaller<Spec>,
    /// Receipt builder.
    pub receipt_builder: R,

    /// Receipts of executed transactions.
    pub receipts: Vec<R::Receipt>,
    /// Total gas used by transactions in this block.
    gas_used: u64,
}

impl<'a, Evm, Spec, R> TaikoBlockExecutor<'a, Evm, Spec, R>
where
    Spec: Clone,
    R: ReceiptBuilder,
{
    /// Creates a new [`TaikoBlockExecutor`]
    pub fn new(evm: Evm, ctx: TaikoBlockExecutionCtx<'a>, spec: Spec, receipt_builder: R) -> Self {
        Self {
            evm,
            ctx,
            receipts: Vec::new(),
            gas_used: 0,
            system_caller: SystemCaller::new(spec.clone()),
            spec,
            receipt_builder,
        }
    }
}

impl<'db, DB, E, Spec, R> BlockExecutor for TaikoBlockExecutor<'_, E, Spec, R>
where
    DB: Database + 'db,
    E: Evm<
            DB = &'db mut State<DB>,
            Tx: FromRecoveredTx<R::Transaction> + FromTxWithEncoded<R::Transaction>,
        >,
    Spec: EthExecutorSpec,
    R: ReceiptBuilder<Transaction: Transaction + Encodable2718, Receipt: TxReceipt<Log = Log>>,
{
    /// Input transaction type.
    type Transaction = R::Transaction;
    /// Receipt type this executor produces.
    type Receipt = R::Receipt;
    /// EVM used by the executor.
    type Evm = E;

    /// Applies any necessary changes before executing the block's transactions.
    /// NOTE: Here we use a system call to set the Anchor transact sender account information and
    /// decode the base fee share percentage from the block's extra data.
    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        // Set state clear flag if the block is after the Spurious Dragon hardfork.
        let state_clear_flag = self
            .spec
            .is_spurious_dragon_active_at_block(self.evm.block().number);
        self.evm.db_mut().set_state_clear_flag(state_clear_flag);

        self.system_caller
            .apply_blockhashes_contract_call(self.ctx.parent_hash, &mut self.evm)?;

        Ok(())
    }

    /// Executes a single transaction and applies execution result to internal state. Invokes the
    /// given closure with an internal [`ExecutionResult`] produced by the EVM, and commits the
    /// transaction to the state on [`CommitChanges::Yes`].
    ///
    /// Returns [`None`] if transaction was skipped via [`CommitChanges::No`].
    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        // The sum of the transaction's gas limit, Tg, and the gas utilized in this block prior,
        // must be no greater than the block's gasLimit.
        let block_available_gas = self.evm.block().gas_limit - self.gas_used;

        if tx.tx().gas_limit() > block_available_gas {
            return Err(
                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: tx.tx().gas_limit(),
                    block_available_gas,
                }
                .into(),
            );
        }

        let ResultAndState { result, state } = if self
            .ctx
            .anchor_transaction_hash
            .is_some_and(|h| tx.tx().trie_hash() == h)
        {
            // If the transaction is an Anchor transaction, we need to use the system call to
            // execute it to skip the balance check and fee sharing.
            self.evm
                .transact_system_call(
                    Address::from(TAIKO_GOLDEN_TOUCH_ADDRESS),
                    tx.tx().to().unwrap(),
                    tx.tx().input().clone(),
                )
                .map_err(|err| BlockExecutionError::evm(err, tx.tx().trie_hash()))?
        } else {
            self.evm
                .transact(tx)
                .map_err(|err| BlockExecutionError::evm(err, tx.tx().trie_hash()))?
        };

        if !f(&result).should_commit() {
            return Ok(None);
        }

        self.system_caller
            .on_state(StateChangeSource::Transaction(self.receipts.len()), &state);

        let gas_used = result.gas_used();

        // append gas used
        self.gas_used += gas_used;

        // Push transaction changeset and calculate header bloom filter for receipt.
        self.receipts
            .push(self.receipt_builder.build_receipt(ReceiptBuilderCtx {
                tx: tx.tx(),
                evm: &self.evm,
                result,
                state: &state,
                cumulative_gas_used: self.gas_used,
            }));

        // Commit the state changes.
        self.evm.db_mut().commit(state);

        Ok(Some(gas_used))
    }

    /// Applies any necessary changes after executing the block's transactions, completes execution
    /// and returns the underlying EVM along with execution result.
    fn finish(self) -> Result<(Self::Evm, BlockExecutionResult<R::Receipt>), BlockExecutionError> {
        Ok((
            self.evm,
            BlockExecutionResult {
                receipts: self.receipts,
                requests: Requests::default(),
                gas_used: self.gas_used,
            },
        ))
    }

    /// Sets a hook to be called after each state change during execution.
    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.system_caller.with_state_hook(hook);
    }

    /// Exposes mutable reference to EVM.
    fn evm_mut(&mut self) -> &mut Self::Evm {
        &mut self.evm
    }

    /// Exposes immutable reference to EVM.
    fn evm(&self) -> &Self::Evm {
        &self.evm
    }
}
