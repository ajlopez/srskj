package co.rsk.config;

import co.rsk.bitcoinj.core.BtcECKey;
import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.NetworkParameters;
import com.google.common.collect.Lists;
import org.ethereum.crypto.ECKey;
import org.bouncycastle.util.encoders.Hex;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class BridgeMainNetConstants extends BridgeConstants {
    private static BridgeMainNetConstants instance = new BridgeMainNetConstants();

    BridgeMainNetConstants() {
        btcParamsString = NetworkParameters.ID_MAINNET;
    }

    public static BridgeMainNetConstants getInstance() {
        return instance;
    }
}
