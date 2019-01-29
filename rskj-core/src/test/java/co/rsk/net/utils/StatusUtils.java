package co.rsk.net.utils;

import co.rsk.core.bc.Blockchain;
import co.rsk.net.Status;

public class StatusUtils {
    public static Status fromBlockchain(Blockchain blockchain) {
        return new Status(
                blockchain.getBestBlock().getNumber(),
                blockchain.getBestBlockHash(),
                blockchain.getBestBlock().getParentHash().getBytes(),
                blockchain.getTotalDifficulty()
        );
    }

    public static Status getFakeStatus() {
        return new Status(0, null);
    }
}
