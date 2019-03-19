package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;

/**
 * Wrapper around parameters to use for or returned by {@link AESEncryption} encryption/decryption methods
 */
public class AESCipher {

    /**
     * the encrypted/decrypted data bytes
     */
    private byte[] dataBytes;

    /**
     * the IV used or to be used for encryption/decryption of the data
     */
    private byte[] iv;

    /**
     * Constructor by specifying the data to encrypt/decrypt or that
     * has just been encrypted/decrypted and the IV to use or that has just been used
     * @param dataBytes the data
     * @param iv the IV
     */
    public AESCipher(byte[] dataBytes, byte[] iv) {
        this.dataBytes = dataBytes;
        this.iv = iv;
    }

    /**
     * Constructor by specifying the data to encrypt/decrypt or that
     * has just been encrypted/decrypted and the IV to use or that has just been used
     * @param dataBytes the data
     * @param hexIv the hexadecimal-encoded bytes of the IV
     */
    public AESCipher(byte[] dataBytes, String hexIv) {
        this(dataBytes, HexString.decode(hexIv));
    }

    /**
     * Constructor by specifying the data to encrypt/decrypt or that
     * has just been encrypted/decrypted and the IV to use or that has just been used
     * @param hexData the hexadecimal-encoded bytes of the data
     * @param hexIv the hexadecimal-encoded bytes of the IV
     */
    public AESCipher(String hexData, String hexIv) {
        this(HexString.decode(hexData), HexString.decode(hexIv));
    }

    /**
     * Performs the hexadecimal-encoding of the data bytes
     * @return the hexadecimal-encoded data bytes
     */
    public String encodeDataBytes() {
        return HexString.encode(dataBytes);
    }

    /**
     * Performs the hexadecimal-encoding of the IV bytes
     * @return the hexadecimal-encoded IV bytes
     */
    public String encodeIv() {
        return HexString.encode(iv);
    }

    /**
     * Returns the data bytes
     * @return the data bytes
     */
    public byte[] getDataBytes() {
        return dataBytes;
    }

    /**
     * Returns the IV
     * @return the IV
     */
    public byte[] getIv() {
        return iv;
    }
}
