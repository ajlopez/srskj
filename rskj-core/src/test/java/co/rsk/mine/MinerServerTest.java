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

package co.rsk.mine;

import co.rsk.bitcoinj.core.*;
import co.rsk.bitcoinj.params.RegTestParams;
import co.rsk.config.ConfigUtils;
import co.rsk.config.TestSystemProperties;
import co.rsk.core.DifficultyCalculator;
import co.rsk.core.bc.Blockchain;
import co.rsk.validators.BlockUnclesValidationRule;
import co.rsk.validators.BlockValidationRule;
import co.rsk.validators.ProofOfWorkRule;
import org.ethereum.core.*;
import org.ethereum.db.BlockStore;
import org.ethereum.db.ReceiptStore;
import org.ethereum.facade.Ethereum;
import org.ethereum.facade.EthereumImpl;
import org.ethereum.rpc.TypeConverter;
import org.ethereum.util.RskTestFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Created by adrian.eidelman on 3/16/2016.
 */
public class MinerServerTest extends ParameterizedNetworkUpgradeTest {

    private final DifficultyCalculator difficultyCalculator;
    private Blockchain blockchain;
    private Repository repository;
    private BlockStore blockStore;
    private TransactionPool transactionPool;

    public MinerServerTest(TestSystemProperties config) {
        super(config);
        this.difficultyCalculator = new DifficultyCalculator(config);
    }

    @Before
    public void setUp() {
        RskTestFactory factory = new RskTestFactory(config);
        blockchain = factory.getBlockchain();
        repository = factory.getRepository();
        blockStore = factory.getBlockStore();
        transactionPool = factory.getTransactionPool();
    }
    
    @Test
    public void submitBitcoinBlockTwoTags() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);
        Mockito.when(ethereumImpl.addNewMinedBlock(Mockito.any())).thenReturn(ImportResult.IMPORTED_BEST);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
        byte[] extraData = ByteBuffer.allocate(4).putInt(1).array();
        minerServer.setExtraData(extraData);
        minerServer.start();
        MinerWork work = minerServer.getWork();
        Block bestBlock = blockchain.getBestBlock();

        extraData = ByteBuffer.allocate(4).putInt(2).array();
        minerServer.setExtraData(extraData);
        minerServer.buildBlockToMine(bestBlock, false);
        MinerWork work2 = minerServer.getWork(); // only the tag is used
        Assert.assertNotEquals(work2.getBlockHashForMergedMining(),work.getBlockHashForMergedMining());

        BtcBlock bitcoinMergedMiningBlock = getMergedMiningBlockWithTwoTags(work,work2);

        findNonce(work, bitcoinMergedMiningBlock);
        SubmitBlockResult result;
        result = ((MinerServerImpl) minerServer).submitBitcoinBlock(work2.getBlockHashForMergedMining(), bitcoinMergedMiningBlock,true);


        Assert.assertEquals("OK", result.getStatus());
        Assert.assertNotNull(result.getBlockInfo());
        Assert.assertEquals("0x1", result.getBlockInfo().getBlockIncludedHeight());
        Assert.assertEquals("0x494d504f525445445f42455354", result.getBlockInfo().getBlockImportedResult());

        // Submit again the save PoW for a different header
        result = ((MinerServerImpl) minerServer).submitBitcoinBlock(work.getBlockHashForMergedMining(), bitcoinMergedMiningBlock,false);

        Assert.assertEquals("ERROR", result.getStatus());

        Mockito.verify(ethereumImpl, Mockito.times(1)).addNewMinedBlock(Mockito.any());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void submitBitcoinBlock() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);
        Mockito.when(ethereumImpl.addNewMinedBlock(Mockito.any())).thenReturn(ImportResult.IMPORTED_BEST);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
            minerServer.start();
            MinerWork work = minerServer.getWork();

            BtcBlock bitcoinMergedMiningBlock = getMergedMiningBlockWithOnlyCoinbase(work);

            findNonce(work, bitcoinMergedMiningBlock);

            SubmitBlockResult result = minerServer.submitBitcoinBlock(work.getBlockHashForMergedMining(), bitcoinMergedMiningBlock);

            Assert.assertEquals("OK", result.getStatus());
            Assert.assertNotNull(result.getBlockInfo());
            Assert.assertEquals("0x1", result.getBlockInfo().getBlockIncludedHeight());
            Assert.assertEquals("0x494d504f525445445f42455354", result.getBlockInfo().getBlockImportedResult());

            Mockito.verify(ethereumImpl, Mockito.times(1)).addNewMinedBlock(Mockito.any());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void submitBitcoinBlockPartialMerkleWhenBlockIsEmpty() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);
        Mockito.when(ethereumImpl.addNewMinedBlock(Mockito.any())).thenReturn(ImportResult.IMPORTED_BEST);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
            minerServer.start();
            MinerWork work = minerServer.getWork();

            BtcBlock bitcoinMergedMiningBlock = getMergedMiningBlockWithOnlyCoinbase(work);

            findNonce(work, bitcoinMergedMiningBlock);

            //noinspection ConstantConditions
            BtcTransaction coinbase = bitcoinMergedMiningBlock.getTransactions().get(0);
            List<String> coinbaseReversedHash = Collections.singletonList(Sha256Hash.wrap(coinbase.getHash().getReversedBytes()).toString());
            SubmitBlockResult result = minerServer.submitBitcoinBlockPartialMerkle(work.getBlockHashForMergedMining(), bitcoinMergedMiningBlock, coinbase, coinbaseReversedHash, 1);

            Assert.assertEquals("OK", result.getStatus());
            Assert.assertNotNull(result.getBlockInfo());
            Assert.assertEquals("0x1", result.getBlockInfo().getBlockIncludedHeight());
            Assert.assertEquals("0x494d504f525445445f42455354", result.getBlockInfo().getBlockImportedResult());

            Mockito.verify(ethereumImpl, Mockito.times(1)).addNewMinedBlock(Mockito.any());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void submitBitcoinBlockPartialMerkleWhenBlockHasTransactions() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);
        Mockito.when(ethereumImpl.addNewMinedBlock(Mockito.any())).thenReturn(ImportResult.IMPORTED_BEST);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
            minerServer.start();
            MinerWork work = minerServer.getWork();

            BtcTransaction otherTx = Mockito.mock(BtcTransaction.class);
            Sha256Hash otherTxHash = Sha256Hash.wrap("aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd");
            Mockito.when(otherTx.getHash()).thenReturn(otherTxHash);
            Mockito.when(otherTx.getHashAsString()).thenReturn(otherTxHash.toString());

            BtcBlock bitcoinMergedMiningBlock = getMergedMiningBlock(work, Collections.singletonList(otherTx));

            findNonce(work, bitcoinMergedMiningBlock);

            //noinspection ConstantConditions
            BtcTransaction coinbase = bitcoinMergedMiningBlock.getTransactions().get(0);
            String coinbaseReversedHash = Sha256Hash.wrap(coinbase.getHash().getReversedBytes()).toString();
            String otherTxHashReversed = Sha256Hash.wrap(otherTxHash.getReversedBytes()).toString();
            List<String> merkleHashes = Arrays.asList(coinbaseReversedHash, otherTxHashReversed);
            SubmitBlockResult result = minerServer.submitBitcoinBlockPartialMerkle(work.getBlockHashForMergedMining(), bitcoinMergedMiningBlock, coinbase, merkleHashes, 2);

            Assert.assertEquals("OK", result.getStatus());
            Assert.assertNotNull(result.getBlockInfo());
            Assert.assertEquals("0x1", result.getBlockInfo().getBlockIncludedHeight());
            Assert.assertEquals("0x494d504f525445445f42455354", result.getBlockInfo().getBlockImportedResult());

            Mockito.verify(ethereumImpl, Mockito.times(1)).addNewMinedBlock(Mockito.any());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void submitBitcoinBlockTransactionsWhenBlockIsEmpty() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);
        Mockito.when(ethereumImpl.addNewMinedBlock(Mockito.any())).thenReturn(ImportResult.IMPORTED_BEST);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
            minerServer.start();
            MinerWork work = minerServer.getWork();

            BtcBlock bitcoinMergedMiningBlock = getMergedMiningBlockWithOnlyCoinbase(work);

            findNonce(work, bitcoinMergedMiningBlock);

            //noinspection ConstantConditions
            BtcTransaction coinbase = bitcoinMergedMiningBlock.getTransactions().get(0);
            SubmitBlockResult result = minerServer.submitBitcoinBlockTransactions(work.getBlockHashForMergedMining(), bitcoinMergedMiningBlock, coinbase, Collections.singletonList(coinbase.getHashAsString()));

            Assert.assertEquals("OK", result.getStatus());
            Assert.assertNotNull(result.getBlockInfo());
            Assert.assertEquals("0x1", result.getBlockInfo().getBlockIncludedHeight());
            Assert.assertEquals("0x494d504f525445445f42455354", result.getBlockInfo().getBlockImportedResult());

            Mockito.verify(ethereumImpl, Mockito.times(1)).addNewMinedBlock(Mockito.any());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void submitBitcoinBlockTransactionsWhenBlockHasTransactions() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);
        Mockito.when(ethereumImpl.addNewMinedBlock(Mockito.any())).thenReturn(ImportResult.IMPORTED_BEST);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
            minerServer.start();
            MinerWork work = minerServer.getWork();

            BtcTransaction otherTx = Mockito.mock(BtcTransaction.class);
            Sha256Hash otherTxHash = Sha256Hash.wrap("aaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccddddaaaabbbbccccdddd");
            Mockito.when(otherTx.getHash()).thenReturn(otherTxHash);
            Mockito.when(otherTx.getHashAsString()).thenReturn(otherTxHash.toString());

            BtcBlock bitcoinMergedMiningBlock = getMergedMiningBlock(work, Collections.singletonList(otherTx));

            findNonce(work, bitcoinMergedMiningBlock);

            //noinspection ConstantConditions
            BtcTransaction coinbase = bitcoinMergedMiningBlock.getTransactions().get(0);
            List<String> txs = Arrays.asList(coinbase.getHashAsString(), otherTxHash.toString());
            SubmitBlockResult result = minerServer.submitBitcoinBlockTransactions(work.getBlockHashForMergedMining(), bitcoinMergedMiningBlock, coinbase, txs);

            Assert.assertEquals("OK", result.getStatus());
            Assert.assertNotNull(result.getBlockInfo());
            Assert.assertEquals("0x1", result.getBlockInfo().getBlockIncludedHeight());
            Assert.assertEquals("0x494d504f525445445f42455354", result.getBlockInfo().getBlockImportedResult());

            Mockito.verify(ethereumImpl, Mockito.times(1)).addNewMinedBlock(Mockito.any());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void workWithNoTransactionsZeroFees() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                this.blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );

        minerServer.start();
        try {
        MinerWork work = minerServer.getWork();

        assertEquals("0", work.getFeesPaidToMiner());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void initialWorkTurnsNotifyFlagOn() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                this.blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
        minerServer.start();

        MinerWork work = minerServer.getWork();

        assertEquals(true, work.getNotify());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void secondWorkWithNoChangesTurnsNotifyFlagOff() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                this.blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );

        minerServer.start();
        try {
        MinerWork work = minerServer.getWork();

        assertEquals(true, work.getNotify());

        work = minerServer.getWork();

        assertEquals(false, work.getNotify());
        } finally {
            minerServer.stop();
        }
    }

    @Test
    public void secondBuildBlockToMineTurnsNotifyFlagOff() {
        EthereumImpl ethereumImpl = Mockito.mock(EthereumImpl.class);

        BlockUnclesValidationRule unclesValidationRule = Mockito.mock(BlockUnclesValidationRule.class);
        Mockito.when(unclesValidationRule.isValid(Mockito.any())).thenReturn(true);
        MinerClock clock = new MinerClock(true, Clock.systemUTC());
        MinerServer minerServer = new MinerServerImpl(
                config,
                ethereumImpl,
                this.blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                new BlockToMineBuilder(
                        ConfigUtils.getDefaultMiningConfig(),
                        repository,
                        blockStore,
                        transactionPool,
                        difficultyCalculator,
                        new GasLimitCalculator(config),
                        unclesValidationRule,
                        config,
                        null,
                        clock
                ),
                clock,
                ConfigUtils.getDefaultMiningConfig()
        );
        try {
        minerServer.start();

        MinerWork work = minerServer.getWork();

        String hashForMergedMining = work.getBlockHashForMergedMining();

        minerServer.buildBlockToMine(blockchain.getBestBlock(), false);

        work = minerServer.getWork();
        assertEquals(hashForMergedMining, work.getBlockHashForMergedMining());
        assertEquals(false, work.getNotify());
        } finally {
            minerServer.stop();
        }
    }

    private BtcBlock getMergedMiningBlockWithOnlyCoinbase(MinerWork work) {
        return getMergedMiningBlock(work, Collections.emptyList());
    }

    private BtcBlock getMergedMiningBlock(MinerWork work, List<BtcTransaction> txs) {
        NetworkParameters bitcoinNetworkParameters = RegTestParams.get();
        BtcTransaction bitcoinMergedMiningCoinbaseTransaction = MinerUtils.getBitcoinMergedMiningCoinbaseTransaction(bitcoinNetworkParameters, work);

        List<BtcTransaction> blockTxs = new ArrayList<>();
        blockTxs.add(bitcoinMergedMiningCoinbaseTransaction);
        blockTxs.addAll(txs);

        return MinerUtils.getBitcoinMergedMiningBlock(bitcoinNetworkParameters, blockTxs);
    }

    private BtcBlock getMergedMiningBlockWithTwoTags(MinerWork work, MinerWork work2) {
        NetworkParameters bitcoinNetworkParameters = RegTestParams.get();
        BtcTransaction bitcoinMergedMiningCoinbaseTransaction =
                MinerUtils.getBitcoinMergedMiningCoinbaseTransactionWithTwoTags(bitcoinNetworkParameters, work, work2);
        return MinerUtils.getBitcoinMergedMiningBlock(bitcoinNetworkParameters, bitcoinMergedMiningCoinbaseTransaction);
    }

    private void findNonce(MinerWork work, BtcBlock bitcoinMergedMiningBlock) {
        BigInteger target = new BigInteger(TypeConverter.stringHexToByteArray(work.getTarget()));

        while (true) {
            try {
                // Is our proof of work valid yet?
                BigInteger blockHashBI = bitcoinMergedMiningBlock.getHash().toBigInteger();
                if (blockHashBI.compareTo(target) <= 0) {
                    break;
                }
                // No, so increment the nonce and try again.
                bitcoinMergedMiningBlock.setNonce(bitcoinMergedMiningBlock.getNonce() + 1);
            } catch (VerificationException e) {
                throw new RuntimeException(e); // Cannot happen.
            }
        }
    }

    private MinerServerImpl getMinerServerWithMocks() {
        return new MinerServerImpl(
                config,
                Mockito.mock(Ethereum.class),
                blockchain,
                null,
                new ProofOfWorkRule(config).setFallbackMiningEnabled(false),
                getBuilderWithMocks(),
                new MinerClock(true, Clock.systemUTC()),
                ConfigUtils.getDefaultMiningConfig()
        );
    }

    private BlockToMineBuilder getBuilderWithMocks() {
        return new BlockToMineBuilder(
                ConfigUtils.getDefaultMiningConfig(),
                Mockito.mock(Repository.class),
                blockStore,
                Mockito.mock(TransactionPool.class),
                difficultyCalculator,
                new GasLimitCalculator(config),
                Mockito.mock(BlockValidationRule.class),
                config,
                Mockito.mock(ReceiptStore.class),
                Mockito.mock(MinerClock.class)
        );
    }
}
