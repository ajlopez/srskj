/*
 * This file is part of RskJ
 * Copyright (C) 2018 RSK Labs Ltd.
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

package co.rsk.rpc;

import co.rsk.core.bc.Blockchain;
import co.rsk.mine.BlockToMineBuilder;
import co.rsk.mine.MinerServer;
import org.ethereum.core.Block;
import org.ethereum.rpc.exception.JsonRpcInvalidParamException;
import org.junit.Before;
import org.junit.Test;

import java.util.Optional;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.*;

public class ExecutionBlockRetrieverTest {

    private Blockchain blockchain;
    private BlockToMineBuilder builder;
    private ExecutionBlockRetriever retriever;

    @Before
    public void setUp() {
        blockchain = mock(Blockchain.class);
        builder = mock(BlockToMineBuilder.class);
        retriever = new ExecutionBlockRetriever(blockchain, builder);
    }

    @Test
    public void getLatest() {
        Block latest = mock(Block.class);
        when(blockchain.getBestBlock())
                .thenReturn(latest);

        assertThat(retriever.getExecutionBlock("latest"), is(latest));
    }

    @Test
    public void getLatestIsUpToDate() {
        Block latest1 = mock(Block.class);
        Block latest2 = mock(Block.class);
        when(blockchain.getBestBlock())
                .thenReturn(latest1)
                .thenReturn(latest2);

        assertThat(retriever.getExecutionBlock("latest"), is(latest1));
        assertThat(retriever.getExecutionBlock("latest"), is(latest2));
    }

    @Test
    public void getPendingBuildsPendingBlockIfMinerServerHasNoWork() {
        Block bestBlock = mock(Block.class);
        when(blockchain.getBestBlock())
                .thenReturn(bestBlock);

        Block builtBlock = mock(Block.class);
        when(builder.build(bestBlock, null))
                .thenReturn(builtBlock);

        assertThat(retriever.getExecutionBlock("pending"), is(builtBlock));
    }

    @Test
    public void getPendingDoesntUseCacheIfBestBlockHasChanged() {
        Block bestBlock1 = mock(Block.class);
        Block bestBlock2 = mock(Block.class);
        when(blockchain.getBestBlock())
                .thenReturn(bestBlock1)
                .thenReturn(bestBlock2);

        Block builtBlock1 = mock(Block.class);
        when(bestBlock1.isParentOf(builtBlock1))
                .thenReturn(true);
        when(builder.build(bestBlock1, null))
                .thenReturn(builtBlock1);
        Block builtBlock2 = mock(Block.class);
        when(bestBlock2.isParentOf(builtBlock2))
                .thenReturn(true);
        when(builder.build(bestBlock2, null))
                .thenReturn(builtBlock2);

        assertThat(retriever.getExecutionBlock("pending"), is(builtBlock1));
        assertThat(retriever.getExecutionBlock("pending"), is(builtBlock2));
    }

    @Test
    public void getByNumberBlockExistsHex() {
        Block myBlock = mock(Block.class);
        when(blockchain.getBlockByNumber(123))
                .thenReturn(myBlock);

        assertThat(retriever.getExecutionBlock("0x7B"), is(myBlock));
        assertThat(retriever.getExecutionBlock("0x7b"), is(myBlock));
    }

    @Test
    public void getByNumberBlockExistsDec() {
        Block myBlock = mock(Block.class);
        when(blockchain.getBlockByNumber(123))
                .thenReturn(myBlock);

        assertThat(retriever.getExecutionBlock("123"), is(myBlock));
    }

    @Test(expected = JsonRpcInvalidParamException.class)
    public void getByNumberInvalidBlockNumberHex() {
        when(blockchain.getBlockByNumber(123))
                .thenReturn(null);

        retriever.getExecutionBlock("0x7B");
    }

    @Test(expected = JsonRpcInvalidParamException.class)
    public void getByNumberInvalidBlockNumberDec() {
        when(blockchain.getBlockByNumber(123))
                .thenReturn(null);

        retriever.getExecutionBlock("123");
    }

    @Test(expected = JsonRpcInvalidParamException.class)
    public void getByNumberInvalidHex() {
        retriever.getExecutionBlock("0xzz");

        verify(blockchain, never()).getBlockByNumber(any(long.class));
    }

    @Test(expected = JsonRpcInvalidParamException.class)
    public void getByNumberInvalidDec() {
        retriever.getExecutionBlock("zz");

        verify(blockchain, never()).getBlockByNumber(any(long.class));
    }

    @Test(expected = JsonRpcInvalidParamException.class)
    public void getOtherThanPendingLatestOrNumberThrows() {
        retriever.getExecutionBlock("other");
    }
}
