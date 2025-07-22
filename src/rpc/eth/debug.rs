use std::fmt::Debug;
use std::sync::Arc;

use alloy_consensus::Header;
use alloy_hardforks::EthereumHardforks;
use alloy_primitives::B256;
use alloy_rpc_types_debug::ExecutionWitness;
use jsonrpsee::tokio::sync::{Semaphore, oneshot};
use jsonrpsee_core::{RpcResult, async_trait};
use reth::tasks::TaskSpawner;
use reth_node_api::NodePrimitives;
use reth_provider::{BlockReaderIdExt, HeaderProvider, NodePrimitivesProvider, StateProvider};
use reth_provider::{ChainSpecProvider, StateProviderFactory};
pub use reth_rpc_api::DebugExecutionWitnessApiServer;
use reth_rpc_server_types::result::internal_rpc_err;

use crate::payload::attributes::TaikoPayloadAttributes;
use crate::payload::builder::TaikoPayloadBuilder;

/// An extension to the `debug_` namespace of the RPC API.
pub struct TaikoDebugWitnessApi<Client, Provider> {
    provider: Provider,
    task_spawner: Box<dyn TaskSpawner>,
    builder: Arc<TaikoPayloadBuilder<Client>>,
    semaphore: Arc<Semaphore>,
}

impl<Client, Provider> TaikoDebugWitnessApi<Client, Provider>
where
    Provider: NodePrimitivesProvider<Primitives: NodePrimitives<BlockHeader = Provider::Header>>
        + HeaderProvider<Header = Header>
        + BlockReaderIdExt
        + Clone,
{
    /// Creates a new instance of `TaikoDebugWitnessApi`.
    pub fn new(
        provider: Provider,
        task_spawner: Box<dyn TaskSpawner>,
        builder: TaikoPayloadBuilder<Client>,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(3));

        Self {
            provider,
            task_spawner,
            builder: Arc::new(builder),
            semaphore,
        }
    }
}

impl<Client, Provider> Clone for TaikoDebugWitnessApi<Client, Provider>
where
    Provider: Clone,
{
    /// Returns a copy of the value.
    fn clone(&self) -> Self {
        Self {
            provider: self.provider.clone(),
            task_spawner: self.task_spawner.clone(),
            builder: Arc::clone(&self.builder),
            semaphore: Arc::clone(&self.semaphore),
        }
    }
}
impl<Client, Provider> Debug for TaikoDebugWitnessApi<Client, Provider> {
    /// Formats the value using the given formatter.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaikoDebugWitnessApi")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<Client, Provider> DebugExecutionWitnessApiServer<TaikoPayloadAttributes>
    for TaikoDebugWitnessApi<Client, Provider>
where
    Provider: NodePrimitivesProvider<Primitives: NodePrimitives<BlockHeader = Provider::Header>>
        + HeaderProvider<Header = Header>
        + BlockReaderIdExt
        + Clone
        + StateProvider
        + 'static,
    Client:
        StateProviderFactory + ChainSpecProvider<ChainSpec: EthereumHardforks> + Clone + 'static,
{
    /// The `debug_executePayload` method allows for re-execution of a group of transactions with
    /// the purpose of generating an execution witness. The witness comprises of a map of all
    /// hashed trie nodes to their preimages that were required during the execution of the block,
    /// including during state root recomputation.
    ///
    /// The first argument is the parent block hash. The second argument is the payload
    /// attributes for the new block.
    async fn execute_payload(
        &self,
        parent_block_hash: B256,
        attributes: TaikoPayloadAttributes,
    ) -> RpcResult<ExecutionWitness> {
        let _permit = self.semaphore.acquire().await;

        let (tx, rx) = oneshot::channel();
        let builder = self.builder.clone();
        let provider = self.provider.clone();
        self.task_spawner.spawn_blocking(Box::pin(async move {
            let res = <TaikoPayloadBuilder<Client> as Clone>::clone(&builder).witness(
                provider,
                parent_block_hash,
                attributes,
            );
            let _ = tx.send(res);
        }));

        rx.await
            .map_err(|err| internal_rpc_err(err.to_string()))?
            .map_err(|err| internal_rpc_err(err.to_string()))
    }
}
