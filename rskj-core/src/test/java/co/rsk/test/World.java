/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package co.rsk.test;

import co.rsk.config.TestSystemProperties;
import co.rsk.core.bc.Blockchain;
import co.rsk.core.bc.BlockchainTest;
import co.rsk.core.bc.BlockExecutor;
import co.rsk.crypto.Keccak256;
import co.rsk.net.BlockNodeInformation;
import co.rsk.net.BlockStore;
import co.rsk.net.BlockSyncService;
import co.rsk.net.NodeBlockProcessor;
import co.rsk.net.sync.SyncConfiguration;
import co.rsk.test.builders.BlockChainBuilder;
import org.ethereum.core.*;
import org.ethereum.db.ReceiptStore;
import org.ethereum.vm.PrecompiledContracts;
import org.ethereum.vm.program.invoke.ProgramInvokeFactoryImpl;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by ajlopez on 8/7/2016.
 */
public class World {
    private Blockchain blockChain;
    private NodeBlockProcessor blockProcessor;
    private BlockExecutor blockExecutor;
    private Map<String, Block> blocks = new HashMap<>();
    private Map<String, Account> accounts = new HashMap<>();
    private Map<String, Transaction> transactions = new HashMap<>();

    public World() {
        this(new BlockChainBuilder().build());
    }

    public World(Repository repository) {
        this(new BlockChainBuilder().setRepository(repository).build());
    }

    public World(ReceiptStore receiptStore) {
        this(new BlockChainBuilder().setReceiptStore(receiptStore).build());
    }

    public World(Blockchain blockChain) {
        this(blockChain, null);
    }

    public World(Blockchain blockChain, Genesis genesis) {
        this.blockChain = blockChain;

        if (genesis == null) {
            genesis = (Genesis) BlockchainTest.getGenesisBlock(blockChain);
            this.blockChain.setStatus(genesis, genesis.getCumulativeDifficulty());
        }

        this.saveBlock("g00", genesis);

        BlockStore store = new BlockStore();
        BlockNodeInformation nodeInformation = new BlockNodeInformation();
        SyncConfiguration syncConfiguration = SyncConfiguration.IMMEDIATE_FOR_TESTING;
        TestSystemProperties config = new TestSystemProperties();
        BlockSyncService blockSyncService = new BlockSyncService(config, store, blockChain, nodeInformation, syncConfiguration);
        this.blockProcessor = new NodeBlockProcessor(store, blockChain, nodeInformation, blockSyncService, syncConfiguration);
    }

    public NodeBlockProcessor getBlockProcessor() { return this.blockProcessor; }

    public BlockExecutor getBlockExecutor() {
        final ProgramInvokeFactoryImpl programInvokeFactory = new ProgramInvokeFactoryImpl();
        final TestSystemProperties config = new TestSystemProperties();
        if (this.blockExecutor == null)
            this.blockExecutor = new BlockExecutor(this.getRepository(), (tx1, coinbase, track1, block1, totalGasUsed1) -> new TransactionExecutor(
                    tx1,
                    block1.getCoinbase(),
                    track1,
                    this.getBlockChain().getBlockStore(),
                    null,
                    programInvokeFactory,
                    block1,
                    null,
                    totalGasUsed1,
                    config.getVmConfig(),
                    config.getBlockchainConfig(),
                    config.playVM(),
                    config.vmTrace(),
                    new PrecompiledContracts(config),
                    config.databaseDir(),
                    config.vmTraceDir(),
                    config.vmTraceCompressed()
            ));

        return this.blockExecutor;
    }

    public Blockchain getBlockChain() { return this.blockChain; }

    public Block getBlockByName(String name) {
        return blocks.get(name);
    }

    public Block getBlockByHash(Keccak256 hash) {
        for (Block block : blocks.values()) {
            if (block.getHash().equals(hash)) {
                return block;
            }
        }

        return null;
    }

    public void saveBlock(String name, Block block) {
        blocks.put(name, block);
    }

    public Account getAccountByName(String name) { return accounts.get(name); }

    public void saveAccount(String name, Account account) { accounts.put(name, account); }

    public Transaction getTransactionByName(String name) { return transactions.get(name); }

    public void saveTransaction(String name, Transaction transaction) { transactions.put(name, transaction); }

    public Repository getRepository() {
        return this.blockChain.getRepository();
    }
}
