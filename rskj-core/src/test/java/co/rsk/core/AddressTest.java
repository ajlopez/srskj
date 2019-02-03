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

import org.junit.Assert;
import org.junit.Test;
import org.bouncycastle.util.encoders.DecoderException;

public class AddressTest {
    @Test
    public void testEquals() {
        Address senderA = new Address("0000000000000000000000000000000001000006");
        Address senderB = new Address("0000000000000000000000000000000001000006");
        Address senderC = new Address("0000000000000000000000000000000001000008");
        Address senderD = Address.nullAddress();
        Address senderE = new Address("0x00002000f000000a000000330000000001000006");

        Assert.assertEquals(senderA, senderB);
        Assert.assertNotEquals(senderA, senderC);
        Assert.assertNotEquals(senderA, senderD);
        Assert.assertNotEquals(senderA, senderE);
    }

    @Test
    public void zeroAddress() {
        Address senderA = new Address("0000000000000000000000000000000000000000");
        Address senderB = new Address("0x0000000000000000000000000000000000000000");
        Address senderC = new Address(new byte[20]);

        Assert.assertEquals(senderA, senderB);
        Assert.assertEquals(senderB, senderC);
        Assert.assertNotEquals(Address.nullAddress(), senderC);
    }

    @Test
    public void nullAddress() {
        Assert.assertArrayEquals(Address.nullAddress().getBytes(), new byte[0]);
    }

    @Test(expected = RuntimeException.class)
    public void invalidLongAddress() {
        new Address("00000000000000000000000000000000010000060");
    }

    @Test(expected = RuntimeException.class)
    public void invalidShortAddress() {
        new Address("0000000000000000000000000000000001006");
    }

    @Test
    public void oddLengthAddressPaddedWithOneZero() {
        new Address("000000000000000000000000000000000100006");
    }

    @Test(expected = DecoderException.class)
    public void invalidHexAddress() {
        new Address("000000000000000000000000000000000100000X");
    }

    @Test(expected = NullPointerException.class)
    public void invalidNullAddressBytes() {
        new Address((byte[]) null);
    }

    @Test(expected = NullPointerException.class)
    public void invalidNullAddressString() {
        new Address((String) null);
    }

    @Test(expected = RuntimeException.class)
    public void invalidShortAddressBytes() {
        new Address(new byte[19]);
    }

    @Test(expected = RuntimeException.class)
    public void invalidLongAddressBytes() {
        new Address(new byte[21]);
    }

}
