package co.rsk.core;

import co.rsk.crypto.Keccak256;

import java.util.Random;

/**
 * Created by ajlopez on 26/01/2019.
 */
public class PegTestUtils {
    private static Random random = new Random();

    public static Keccak256 createHash3() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return new Keccak256(bytes);
    }
}
