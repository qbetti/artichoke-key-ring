package ca.uqac.lif.artichoke.keyring;

import org.bouncycastle.util.encoders.Hex;

public class HexString {

    public static String encode(byte[] data) {
        return new String(Hex.encode(data));
    }

    public static byte[] decode(String s) {
        return Hex.decode(s);
    }
}
