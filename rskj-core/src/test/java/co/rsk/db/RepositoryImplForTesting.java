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

package co.rsk.db;

import co.rsk.core.Address;
import co.rsk.trie.Trie;
import org.ethereum.core.AccountState;
import org.ethereum.datasource.HashMapDB;
import org.ethereum.db.ContractDetails;
import org.ethereum.vm.DataWord;

import static org.ethereum.core.AccountState.EMPTY_DATA_HASH;

/**
 * Created by ajlopez on 08/04/2017.
 */
public class RepositoryImplForTesting extends RepositoryImpl {

    public RepositoryImplForTesting() {
        super(new Trie(null, true), new HashMapDB(), new TrieStorePoolOnMemory());
    }

    @Override
    public synchronized void addStorageRow(Address addr, DataWord key, DataWord value) {
        super.addStorageRow(addr, key, value);
        AccountState accountState = getAccountState(addr);
        ContractDetails details = detailsDataStore.get(addr, EMPTY_DATA_HASH);
        accountState.setStateRoot(details.getStorageHash());
        updateAccountState(addr, accountState);
    }

    @Override
    public synchronized void addStorageBytes(Address addr, DataWord key, byte[] value) {
        super.addStorageBytes(addr, key, value);
        AccountState accountState = getAccountState(addr);
        ContractDetails details = detailsDataStore.get(addr, EMPTY_DATA_HASH);
        accountState.setStateRoot(details.getStorageHash());
        updateAccountState(addr, accountState);
    }
}
