package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.*;

public class AESEncryptionTest {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateKeys() {
        SecretKey secretKey0 = AESEncryption.generateNewKey();
        assertNotNull(secretKey0);

        SecretKey secretKey1 = AESEncryption.generateNewKey();
        assertNotNull(secretKey1);

        assertFalse(Arrays.equals(secretKey0.getEncoded(), secretKey1.getEncoded()));
    }

    @Test
    public void testEncryption() {
        byte[] data = "data".getBytes();

        AESEncryption aes0 = new AESEncryption();
        AESCipher encryptedCipher0 = aes0.encrypt(data);
        AESCipher decryptedCipher0 = aes0.decrypt(encryptedCipher0);

        assertNotNull(encryptedCipher0.getIv());
        assertNotNull(decryptedCipher0.getIv());
        assertArrayEquals(encryptedCipher0.getIv(), decryptedCipher0.getIv());

        assertNotNull(encryptedCipher0.getDataBytes());
        assertNotNull(decryptedCipher0.getDataBytes());
        assertArrayEquals(data, decryptedCipher0.getDataBytes());

        String hexSecretKey0 = aes0.encodeSecretKey();
        String hexIv0 = encryptedCipher0.encodeIv();

        AESEncryption aes1 = new AESEncryption(hexSecretKey0);
        AESCipher encryptedCipher1 = aes1.encrypt(new AESCipher(data, hexIv0));
        AESCipher decryptedCipher1 = aes1.decrypt(encryptedCipher1);

        assertEquals(hexIv0, decryptedCipher1.encodeIv());
        assertArrayEquals(encryptedCipher0.getDataBytes(), encryptedCipher1.getDataBytes());
        assertArrayEquals(data, decryptedCipher1.getDataBytes());


        String hexData = HexString.encode(data);
        AESCipher encryptedCipher2 = aes1.encrypt(hexData, hexIv0);
        AESCipher decryptedCipher2 = aes1.decrypt(encryptedCipher2.encodeDataBytes(), encryptedCipher2.encodeIv());

        assertEquals(hexData, decryptedCipher2.encodeDataBytes());
    }

    @Test
    public void testEncryptionFails() {
        byte[] data = "data".getBytes();

        SecretKey secretKey0 = AESEncryption.generateNewKey();
        SecretKey secretKey1 = AESEncryption.generateNewKey();

        AESEncryption aes0 = new AESEncryption(secretKey0);
        AESEncryption aes1 = new AESEncryption(secretKey1);

        // test encryption/decryption with different keys
        assertFalse(Arrays.equals(data, aes1.decrypt(aes0.encrypt(data)).getDataBytes()));
        assertFalse(Arrays.equals(data, aes0.decrypt(aes1.encrypt(data)).getDataBytes()));

        // test encryption/decryption with different IV
        assertFalse(Arrays.equals(
                data,
                aes1.decrypt(aes1.encrypt(data).getDataBytes(), AESEncryption.generateIv(16)).getDataBytes()
        ));
        assertFalse(Arrays.equals(
                data,
                aes0.decrypt(aes0.encrypt(data).getDataBytes(), AESEncryption.generateIv(10)).getDataBytes()
        ));

        // IV null
        assertNull(aes0.encrypt(data, null));

        // IV less than 8-byte long
        assertNull(aes1.decrypt(data, AESEncryption.generateIv(7)));

        // Null key
        AESEncryption aesNull = new AESEncryption((SecretKey) null);
        assertNull(aesNull.encrypt(data));

        // Key size incorrect
        AESEncryption aesBadKeyLength = new AESEncryption(AESEncryption.generateNewKey(31));
        assertNull(aesBadKeyLength.encrypt(data));
    }

    @Test
    public void testECKeyForAES() {
        byte[] data = "data".getBytes();

        ECEncryption ec = new ECEncryption();
        SecretKey secretKey = ec.convertToAESKey();
        AESEncryption aes = new AESEncryption(secretKey);

        AESCipher encryptedCipher = aes.encrypt(data);
        AESCipher decryptedCipher = aes.decrypt(encryptedCipher);

        assertArrayEquals(data, decryptedCipher.getDataBytes());
    }
}
