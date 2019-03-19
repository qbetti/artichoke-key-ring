package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;

import java.security.SecureRandom;

/**
 * Provides a wrapper around {@link org.bouncycastle.crypto.generators.SCrypt} class
 * for scrypt key derivation function and methods to combine it with AES encryption.
 */
public class SCrypt {

    /**
     * Scrypt derivation function parameters to use
     * TODO: more explanation
     */
    private static final int PARALLELISATION_PARAM = 1;
    private static final int BLOCK_SIZE = 8;
    private static final int N = 262144;

    /**
     * Desired size in bytes of the derived key
     */
    private static final int DERIVED_KEY_SIZE = 32; // in bytes

    /**
     * Default size in bytes of the generated salts
     */
    private static final int DEFAULT_SCRYPT_SALT_SIZE = 32; // in bytes

    /**
     * The salt to use for this instance's derivations
     */
    private byte[] salt;

    /**
     * Constructor by specifying the salt bytes that will be used for the SCrypt
     * key derivation function.
     * @param salt the salt bytes. If null, will generate a random
     *              {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte salt
     */
    public SCrypt(byte[] salt) {
        if(salt == null) {
            salt = generateNewSalt();
        }
        this.salt = salt;
    }

    /**
     * Generates a random {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte long salt
     * @return the generated salt
     */
    public static byte[] generateNewSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[DEFAULT_SCRYPT_SALT_SIZE];
        random.nextBytes(salt);
        return salt;
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
     * Encrypts data with AES using the scrypt-generated secret key from a specified passphrase
     * @param data the data to encrypt
     * @param passphrase the passphrase for the scrypt key derivation function
     * @return the cipher containing the encrypted data and the IV used for the encryption
     */
    public AESCipher encryptWithAES(byte[] data, String passphrase) {
        return encryptWithAES(data, passphrase.getBytes());
    }

    /**
     * Encrypts data with AES using the scrypt-generated secret key from a specified passphrase
     * @param data the data to encrypt
     * @param passphrase the passphrase for the scrypt key derivation function
     * @return the cipher containing the encrypted data and the IV used for the encryption
     */
    public AESCipher encryptWithAES(byte[] data, byte[] passphrase) {
        return encryptWithAES(data, null, passphrase);
    }

    /**
     * Encrypts data with AES using the scrypt-generated secret key from a specified passphrase
     * and an IV.
     * @param data the data to encrypt
     * @param iv the IV for the AES encryption (if null, a random IV is generated)
     * @param passphrase the passphrase for the scrypt key derivation function
     * @return the cipher containing the encrypted data and the IV used for the encryption
     */
    public AESCipher encryptWithAES(byte[] data, byte[] iv, byte[] passphrase) {
        byte[] secretKey = deriveKey(passphrase);
        AESEncryption aes = new AESEncryption(secretKey);

        if(iv == null)
            return aes.encrypt(data);
        else
            return aes.encrypt(data, iv);
    }

    /**
     * Decrypts data with AES using the scrypt-generated secret key from a specified passphrase
     * and the corresponding IV
     * @param encryptedData the data to decrypt
     * @param iv the corresponding IV for the AES decryption
     * @param passphrase the passphrase for the scrypt key derivation function
     * @return the cipher containing the decrypted data and the IV used for decryption
     */
    public AESCipher decryptWithAES(byte[] encryptedData, byte[] iv, byte[] passphrase) {
        byte[] secretKey = deriveKey(passphrase);
        AESEncryption aes = new AESEncryption(secretKey);

        return aes.decrypt(encryptedData, iv);
    }

    /**
     * Decrypts data with AES using the scrypt-generated secret key from a specified passphrase
     * @param aesCipher the cipher containing the data to decrypt and the the corresponding IV
     * @param passphrase the passphrase for the scrypt key derivation function
     * @return the cipher containing the decrypted data and the IV used for decryption
     */
    public AESCipher decryptWithAES(AESCipher aesCipher, String passphrase) {
        return decryptWithAES(aesCipher.getDataBytes(), aesCipher.getIv(), passphrase.getBytes());
    }

    /**
     * Decrypts data with AES using the scrypt-generated secret key from a specified passphrase
     * and the corresponding IV
     * @param hexEncryptedData the hexadecimal-encoded data to decrypt
     * @param hexIv the hexadecimal-encoded IV
     * @param passphrase the passphrase for the scrypt key derivation function
     * @return the cipher containing the decrypted data and the IV used for decryption
     */
    public AESCipher decryptWithAES(String hexEncryptedData, String hexIv, String passphrase) {
        return decryptWithAES(new AESCipher(hexEncryptedData, hexIv), passphrase);
    }

    /**
     * Encodes the salt in hexadecimal
     * @return the hexadecimal representation of the salt
     */
    public String encodeSalt() {
        return HexString.encode(salt);
    }
}
