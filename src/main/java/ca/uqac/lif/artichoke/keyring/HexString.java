package ca.uqac.lif.artichoke.keyring;

import org.bouncycastle.util.encoders.Hex;

/**
 * Wrapper around the {@link Hex} encoder, providing methods to
 * perform hexadecimal encoding of data byte and decoding of hexadecimal strings.
 */
public class HexString {

    /**
     * Performs the hexadecimal encoding of data bytes
     * @param data data to encode
     * @return the hexadecimal-encoded data
     */
    public static String encode(byte[] data) {
        return new String(Hex.encode(data));
    }

    /**
     * Performs the hexadecimal decoding of an hexadecimal string
     * @param s the hexadecimal string to decode
     * @return the decoded data bytes
     */
    public static byte[] decode(String s) {
        return Hex.decode(s);
    }
}
