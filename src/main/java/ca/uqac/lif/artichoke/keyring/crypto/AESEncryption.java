package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * Provides a wrapper around AES encryption/decryption from BouncyCastle and secret key generation.
 * The full AES algorithm used is {@value #AES_COUNTER_MODE}, which the AES algorithm
 * with Counter Mode and no padding.
 */
public class AESEncryption {

    /**
     * AES algorithm
     */
    public static final String AES = "AES";

    /**
     * AES algorithm with Counter mode and no padding
     */
    private static final String AES_COUNTER_MODE = "AES/CTR/NoPadding";

    /**
     * Default AES secret key size in bits
     */
    private static final int DEFAULT_KEY_SIZE = 256; // in bits

    /**
     * Default size in bytes for generated IVs
     */
    private static final int DEFAULT_IV_SIZE = 16; // in bytes

    /**
     * The AES secret key used for this instance's encryption/decryption
     */
    private SecretKey secretKey;

    /**
     * Constructor by specifying the secret key used for
     * this instance's encryption/decryption
     * @param hexSecretKey the hexadecimal-encoded bytes of the secret key
     */
    public AESEncryption(String hexSecretKey) {
        this(HexString.decode(hexSecretKey));
    }

    /**
     * Constructor by specifying the secret key used for
     * this instance's encryption/decryption
     * @param secretKey the secret key's bytes
     */
    public AESEncryption(byte[] secretKey) {
        this(convertToAESKey(secretKey));
    }

    /**
     * Constructor by specifying the secret key used for
     * this instance's encryption/decryption
     * @param secretKey the secret key
     */
    public AESEncryption(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    /**
     * Constructor generating a new secret key
     * used for this instance's encryption/decryption
     */
    public AESEncryption() {
        this(generateNewKey());
    }

    /**
     * Generates a new secret key with the specified size
     * @param size the desired size of the generated secret key in bits
     * @return the generated secret key
     */
    public static SecretKey generateNewKey(int size) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES, "BC");
            keyGen.init(size);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Generates a new {@value #DEFAULT_KEY_SIZE}-bit long secret key
     * @return the generated secret key
     */
    public static SecretKey generateNewKey() {
        return generateNewKey(DEFAULT_KEY_SIZE);
    }

    /**
     * Generates a new random IV with the specified size
     * @param size the desired size of the generated IV in bytes
     * @return the generated IV
     */
    public static byte[] generateIv(int size) {
        byte[] iv = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Converts a byte array to a proper {@link SecretKey} object.
     * @param secretKey the byte for the secret key (should respect the authorized sizes for AES)
     * @return the secret key
     */
    public static SecretKey convertToAESKey(byte[] secretKey) {
        return new SecretKeySpec(secretKey, AES);
    }

    /**
     * Encrypts data using {@value #AES_COUNTER_MODE} algorithm and a specified IV
     * @param data the data to encrypt
     * @param iv the IV used for the encryption
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AESCipher encrypt(byte[] data, byte[] iv) {
        byte[] encryptedData = doCipher(Cipher.ENCRYPT_MODE, iv, data);
        if(encryptedData == null)
            return null;

        return new AESCipher(encryptedData, iv);
    }

    /**
     * Encrypts data using {@value #AES_COUNTER_MODE} algorithm and a random IV
     * @param data the data to encrypt
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AESCipher encrypt(byte[] data) {
        return encrypt(data, generateIv(DEFAULT_IV_SIZE));
    }

    /**
     * Encrypts the data of a {@link AESCipher} using {@value #AES_COUNTER_MODE} algorithm
     * and the contained IV
     * @param cipher the cipher containing the data to encrypt and the IV to use
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AESCipher encrypt(AESCipher cipher) {
        return encrypt(cipher.getDataBytes(), cipher.getIv());
    }

    /**
     * Encrypts data using {@value #AES_COUNTER_MODE} algorithm and a specified IV
     * @param hexData the hexadecimal-encoded bytes of the data to encrypt
     * @param hexIv the hexadecimal-encoded bytes of the IV
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AESCipher encrypt(String hexData, String hexIv) {
        return encrypt(new AESCipher(hexData, hexIv));
    }

    /**
     * Decrypts data using {@value #AES_COUNTER_MODE} algorithm and the corresponding IV
     * @param encryptedData the data to decrypt
     * @param iv the IV to use for decryption
     * @return the cipher containing the decrypted data and the IV used for decryption,
     *          or null if data is null
     */
    public AESCipher decrypt(byte[] encryptedData, byte[] iv) {
        byte[] data = doCipher(Cipher.DECRYPT_MODE, iv, encryptedData);
        if(data == null)
            return null;

        return new AESCipher(data, iv);
    }

    /**
     * Decrypts the data of a {@link AESCipher} using {@value #AES_COUNTER_MODE} algorithm
     * and the contained IV
     * @param encryptedCipher the cipher containing the data to encrypt and the IV to use
     * @return the cipher containing the decrypted data and the IV used for decryption
     */
    public AESCipher decrypt(AESCipher encryptedCipher) {
        return decrypt(encryptedCipher.getDataBytes(), encryptedCipher.getIv());
    }

    /**
     * Decrypts data using {@value #AES_COUNTER_MODE} algorithm and the corresponding IV
     * @param hexEncryptedData the hexadecimal-encoded bytes of the data to decrypt
     * @param hexIv the hexadecimal-encoded bytes of the IV to use for decryption
     * @return the cipher containing the decrypted data and the IV used for decryption
     */
    public AESCipher decrypt(String hexEncryptedData, String hexIv) {
        return decrypt(new AESCipher(hexEncryptedData, hexIv));
    }

    /**
     * Performs {@value #AES_COUNTER_MODE} encryption or decryption of the
     * specified data with a specified IV
     * @param cipherMode cipher mode (encryption or decryption)
     * @param iv the IV to use for encryption/decryption
     * @param data the data to encrypt/decrypt
     * @return the encrypted/decrypted data, or null if something goes wrong
     */
    private byte[] doCipher(int cipherMode, byte[] iv, byte[] data) {
        if(iv == null)
            return null;

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(AES_COUNTER_MODE, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        try {
            cipher.init(cipherMode, secretKey, new IvParameterSpec(iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }

        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Performs the hexadecimal-encoding of the secret key
     * @return the hexadecimal-encoded bytes of the secret key
     */
    public String encodeSecretKey() {
        return HexString.encode(secretKey.getEncoded());
    }
}
