package co.rsk.config;

import co.rsk.bitcoinj.core.NetworkParameters;

public class BitcoinMainNetConstants extends BitcoinConstants {
    private static BitcoinMainNetConstants instance = new BitcoinMainNetConstants();

    BitcoinMainNetConstants() {
        btcParamsString = NetworkParameters.ID_MAINNET;
    }

    public static BitcoinMainNetConstants getInstance() {
        return instance;
    }
}
