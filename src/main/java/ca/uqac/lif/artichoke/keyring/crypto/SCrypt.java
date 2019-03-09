package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;

import java.security.SecureRandom;

public class SCrypt {

    private static final int PARALLELISATION_PARAM = 1;
    private static final int BLOCK_SIZE = 8;
    private static final int N = 262144;
    private static final int DERIVED_KEY_SIZE = 32; // in bytes
    private static final int DEFAULT_SCRYPT_SALT_SIZE = 32; // in bytes

    private byte[] salt;

    /**
     * Constructor by specifying the salt bytes that will be used for the SCrypt
     * key derivation function.
     * @param salt the salt bytes. If null, will generate a random
     *              {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte salt
     */
    public SCrypt(byte[] salt) {
        if(salt == null) {
            SecureRandom random = new SecureRandom();
            salt = new byte[DEFAULT_SCRYPT_SALT_SIZE];
            random.nextBytes(salt);
        }
        this.salt = salt;
    }

    /**
     * Constructor by specifying the salt hexadecimal representation that will be used
     * for the SCrypt key derivation function
     * @param hexSalt the hexadecimal representation of the salt
     */
    public SCrypt(String hexSalt) {
        this(HexString.decode(hexSalt));
    }

    /**
     * Constructor that generates a random {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte salt
     */
    public SCrypt() {
        this((byte[]) null);
    }

    /**
     * Generates a 256-bit key derived from the specified passphrase using the SCrypt
     * derivation function
     * @param passphrase the passphrase bytes
     * @return the derived key
     */
    public byte[] deriveKey(byte[] passphrase) {
        return org.bouncycastle.crypto.generators.SCrypt.generate(passphrase, salt, N, BLOCK_SIZE, PARALLELISATION_PARAM, DERIVED_KEY_SIZE);
    }

    /**
     * Generates a 256-bit key derived from the specified passphrase using the SCrypt
     * derivation function
     * @param passphrase the passphrase
     * @return the derived key
     */
    public byte[] deriveKey(String passphrase) {
        return deriveKey(passphrase.getBytes());
    }

    /**
     * Encodes the salt in hexadecimal
     * @return the hexadecimal representation of the salt
     */
    public String encodeSalt() {
        return HexString.encode(salt);
    }
}
