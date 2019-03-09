package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

public class AESEncryption {

    public static final String AES = "AES";
    private static final String AES_COUNTER_MODE = "AES/CTR/NoPadding";
    private static final int KEY_SIZE = 256; // in bits
    private static final int IV_SIZE = 16; // in bytes


    private SecretKey secretKey;
    private byte[] lastIv;

    public AESEncryption(byte[] secretKey) {
        this(convertToAESKey(secretKey));
    }

    public AESEncryption(SecretKey secretKey) {
        this.secretKey = secretKey;
    }

    public AESEncryption() {
        this(generateNewKey());
    }


    public static SecretKey generateNewKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES, "BC");
            keyGen.init(KEY_SIZE);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static SecretKey convertToAESKey(byte[] secretKey) {
        return new SecretKeySpec(secretKey, AES);
    }

    public byte[] encrypt(byte[] data) {
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        return encrypt(data, iv);
    }

    public byte[] encrypt(byte[] data, String hexIv) {
        return encrypt(data, HexString.decode(hexIv));
    }

    public byte[] encrypt(byte[] data, byte[] iv) {
        return doCipher(Cipher.ENCRYPT_MODE, iv, data);
    }

    public byte[] decrypt(byte[] encryptedData, byte[] iv) {
        return doCipher(Cipher.DECRYPT_MODE, iv, encryptedData);
    }


    private byte[] doCipher(int cipherMode, byte[] iv, byte[] data) {
        if(iv == null)
            return null;

        this.lastIv = iv;

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


    public String encodeLastIV() {
        return HexString.encode(lastIv);
    }

    public String encodeSecretKey() {
        return HexString.encode(secretKey.getEncoded());
    }
}
