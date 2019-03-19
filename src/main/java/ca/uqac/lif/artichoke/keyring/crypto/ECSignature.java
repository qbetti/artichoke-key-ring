package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;

/**
 * Wrapper around an elliptic curve signature
 */
public class ECSignature {

    /**
     * The signature bytes
     */
    private byte[] bytes;

    /**
     * Constructor by specifying the signature
     * @param bytes the signature
     */
    public ECSignature(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Constructor by specifying the signature
     * @param hexSignature the hexadecimal-encoded bytes of the signature
     */
    public ECSignature(String hexSignature) {
        this(HexString.decode(hexSignature));
    }

    /**
     * Returns the signature bytes
     * @return the signature bytes
     */
    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Performs the hexadecimal-encoding of the signature bytes
     * @return the hexadecimal-encoded bytes of the signature
     */
    public String encode() {
        return HexString.encode(bytes);
    }
}
