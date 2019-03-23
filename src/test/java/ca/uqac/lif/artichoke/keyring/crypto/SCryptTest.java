package ca.uqac.lif.artichoke.keyring.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.*;

public class SCryptTest {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateSalt() {
        byte[] salt0 = SCrypt.generateNewSalt();
        byte[] salt1 = SCrypt.generateNewSalt();

        assertNotNull(salt0);
        assertNotNull(salt1);
        assertFalse(Arrays.equals(salt0, salt1));
        assertEquals(32, salt0.length);
        assertEquals(32, salt1.length);
    }

    @Test
    public void testEncryption() {
        String passphrase0 = "passphrase0";
        String passphrase1 = "passphrase1";

        SCrypt sCrypt0 = new SCrypt();
        byte[] key0 = sCrypt0.deriveKey(passphrase0);
        byte[] key1 = sCrypt0.deriveKey(passphrase1);

        assertNotNull(key0);
        assertNotNull(key1);
        assertFalse(Arrays.equals(key0, key1));
        assertEquals(32, key0.length);
        assertEquals(32, key1.length);

        SCrypt sCrypt2 = new SCrypt(sCrypt0.encodeSalt());
        byte[] key2 = sCrypt2.deriveKey(passphrase0);
        assertArrayEquals(key0, key2);
        assertEquals(sCrypt0.encodeSalt(), sCrypt2.encodeSalt());


        SCrypt sCrypt3 = new SCrypt();
        byte[] key3 = sCrypt3.deriveKey(passphrase0);
        assertFalse(Arrays.equals(key0, key3));
    }

    @Test
    public void testEncryptionWithAES() {
        String passphrase = "passphrase";
        ECEncryption ec = new ECEncryption();

        SCrypt sCrypt = new SCrypt();
        String hexSalt = sCrypt.encodeSalt();

        AESCipher encryptedPrivateKeyCipher = sCrypt.encryptWithAES(ec.getPrivateKeyBytes(), passphrase);
        String hexEncryptedPrivateKey = encryptedPrivateKeyCipher.encodeDataBytes();
        String hexIv = encryptedPrivateKeyCipher.encodeIv();

        SCrypt sCrypt1 = new SCrypt(hexSalt);
        AESCipher decryptedPrivateKey = sCrypt1.decryptWithAES(hexEncryptedPrivateKey, hexIv, passphrase);

        assertArrayEquals(ec.getPrivateKeyBytes(), decryptedPrivateKey.getDataBytes());

        AESCipher decryptedPrivateKey1 = sCrypt1.decryptWithAES(encryptedPrivateKeyCipher, passphrase);
        assertArrayEquals(ec.getPrivateKeyBytes(), decryptedPrivateKey1.getDataBytes());
    }
}
