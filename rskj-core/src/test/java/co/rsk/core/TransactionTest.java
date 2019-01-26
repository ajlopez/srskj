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

package co.rsk.core;

import co.rsk.config.TestSystemProperties;
import co.rsk.crypto.Keccak256;
import org.ethereum.core.*;
import org.ethereum.crypto.ECKey;
import org.ethereum.crypto.HashUtil;
import org.ethereum.db.BlockStoreDummy;
import org.ethereum.listener.EthereumListenerAdapter;
import org.ethereum.vm.PrecompiledContracts;
import org.ethereum.vm.program.ProgramResult;
import org.junit.Assert;
import org.junit.Test;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class TransactionTest {

    private final TestSystemProperties config = new TestSystemProperties();

    @Test  /* achieve public key of the sender */
    public void test2() throws Exception {
        if (config.getBlockchainConfig().getCommonConstants().getChainId() != 0)
            return;

        // cat --> 79b08ad8787060333663d19704909ee7b1903e58
        // cow --> cd2a3d9f938e13cd947ec05abc7fe734df8dd826

        BigInteger value = new BigInteger("1000000000000000000000");

        byte[] privKey = HashUtil.keccak256("cat".getBytes());
        ECKey ecKey = ECKey.fromPrivate(privKey);

        byte[] senderPrivKey = HashUtil.keccak256("cow".getBytes());

        byte[] gasPrice = Hex.decode("09184e72a000");
        byte[] gas = Hex.decode("4255");

        // Tn (nonce); Tp(pgas); Tg(gaslimi); Tt(value); Tv(value); Ti(sender);  Tw; Tr; Ts
        Transaction tx = new Transaction(null, gasPrice, gas, ecKey.getAddress(),
                value.toByteArray(),
                null);

        tx.sign(senderPrivKey);

        System.out.println("v\t\t\t: " + Hex.toHexString(new byte[]{tx.getSignature().v}));
        System.out.println("r\t\t\t: " + Hex.toHexString(BigIntegers.asUnsignedByteArray(tx.getSignature().r)));
        System.out.println("s\t\t\t: " + Hex.toHexString(BigIntegers.asUnsignedByteArray(tx.getSignature().s)));

        System.out.println("RLP encoded tx\t\t: " + Hex.toHexString(tx.getEncoded()));

        // retrieve the signer/sender of the transaction
        ECKey key = ECKey.signatureToKey(tx.getHash().getBytes(), tx.getSignature());

        System.out.println("Tx unsigned RLP\t\t: " + Hex.toHexString(tx.getEncodedRaw()));
        System.out.println("Tx signed   RLP\t\t: " + Hex.toHexString(tx.getEncoded()));

        System.out.println("Signature public key\t: " + Hex.toHexString(key.getPubKey()));
        System.out.println("Sender is\t\t: " + Hex.toHexString(key.getAddress()));

        assertEquals("cd2a3d9f938e13cd947ec05abc7fe734df8dd826",
                Hex.toHexString(key.getAddress()));

        System.out.println(tx.toString());
    }

    @Test  /* achieve public key of the sender */
    public void testSenderShouldChangeWhenReSigningTx() throws Exception {
        BigInteger value = new BigInteger("1000000000000000000000");

        byte[] privateKey = HashUtil.keccak256("cat".getBytes());
        ECKey ecKey = ECKey.fromPrivate(privateKey);

        byte[] senderPrivateKey = HashUtil.keccak256("cow".getBytes());

        byte[] gasPrice = Hex.decode("09184e72a000");
        byte[] gas = Hex.decode("4255");

        // Tn(nonce); Tp(pgas); Tg(gaslimit); Tt(value); Tv(value); Ti(sender);  Tw; Tr; Ts
        Transaction tx = new Transaction(null, gasPrice, gas, ecKey.getAddress(),
                value.toByteArray(),
                null);

        tx.sign(senderPrivateKey);

        System.out.println("v\t\t\t: " + Hex.toHexString(new byte[]{tx.getSignature().v}));
        System.out.println("r\t\t\t: " + Hex.toHexString(BigIntegers.asUnsignedByteArray(tx.getSignature().r)));
        System.out.println("s\t\t\t: " + Hex.toHexString(BigIntegers.asUnsignedByteArray(tx.getSignature().s)));

        System.out.println("RLP encoded tx\t\t: " + Hex.toHexString(tx.getEncoded()));

        // Retrieve sender from transaction
        RskAddress sender = tx.getSender();

        // Re-sign transaction with a different sender's key
        byte[] newSenderPrivateKey = HashUtil.keccak256("bat".getBytes());
        tx.sign(newSenderPrivateKey);

        // Retrieve new sender from transaction
        RskAddress newSender = tx.getSender();

        // Verify sender changed
        assertNotEquals(sender, newSender);

        System.out.println(tx.toString());
    }

    @Test
    public void testEip155() {
        // Test to match the example provided in https://github.com/ethereum/eips/issues/155
        // Note that vitalik's tx encoded raw hash is wrong and kvhnuke fixes that in a comment
        byte[] nonce = BigInteger.valueOf(9).toByteArray();
        byte[] gasPrice = BigInteger.valueOf(20000000000L).toByteArray();
        byte[] gas = BigInteger.valueOf(21000).toByteArray();
        byte[] to = Hex.decode("3535353535353535353535353535353535353535");
        byte[] value = BigInteger.valueOf(1000000000000000000L).toByteArray();
        byte[] data = new byte[0];
        byte chainId = 1;
        Transaction tx = new Transaction(nonce, gasPrice, gas, to, value, data, chainId);
        byte[] encoded = tx.getEncodedRaw();
        byte[] hash = tx.getRawHash().getBytes();
        String strenc = Hex.toHexString(encoded);
        Assert.assertEquals("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080", strenc);
        String strhash = Hex.toHexString(hash);
        Assert.assertEquals("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53", strhash);
        System.out.println(strenc);
        System.out.println(strhash);
    }

    @Test
    public void testTransaction() {
        Transaction tx = new Transaction(9L, 20000000000L, 21000L,
                "3535353535353535353535353535353535353535", 1000000000000000000L, new byte[0], (byte) 1);

        byte[] encoded = tx.getEncodedRaw();
        byte[] hash = tx.getRawHash().getBytes();
        String strenc = Hex.toHexString(encoded);
        Assert.assertEquals("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080", strenc);
        String strhash = Hex.toHexString(hash);
        Assert.assertEquals("daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53", strhash);
        System.out.println(strenc);
        System.out.println(strhash);
    }

    @Test
    public void isContractCreationWhenReceiveAddressIsNull() {
        Transaction tx = new Transaction(config, null, BigInteger.ONE, BigInteger.TEN, BigInteger.ONE, BigInteger.valueOf(21000L));
        Assert.assertTrue(tx.isContractCreation());
    }

    @Test
    public void isContractCreationWhenReceiveAddressIsEmptyString() {
        Transaction tx = new Transaction(config, "", BigInteger.ONE, BigInteger.TEN, BigInteger.ONE, BigInteger.valueOf(21000L));
        Assert.assertTrue(tx.isContractCreation());
    }

    @Test(expected = RuntimeException.class)
    public void isContractCreationWhenReceiveAddressIs00() {
        new Transaction(config, "00", BigInteger.ONE, BigInteger.TEN, BigInteger.ONE, BigInteger.valueOf(21000L));
    }

    @Test
    public void isContractCreationWhenReceiveAddressIsFortyZeroes() {
        Transaction tx = new Transaction(config, "0000000000000000000000000000000000000000", BigInteger.ONE, BigInteger.TEN, BigInteger.ONE, BigInteger.valueOf(21000L));
        Assert.assertFalse(tx.isContractCreation());
    }

    @Test
    public void isNotContractCreationWhenReceiveAddressIsCowAddress() {
        Transaction tx = new Transaction(config, "cd2a3d9f938e13cd947ec05abc7fe734df8dd826", BigInteger.ONE, BigInteger.TEN, BigInteger.ONE, BigInteger.valueOf(21000L));
        Assert.assertFalse(tx.isContractCreation());
    }
}