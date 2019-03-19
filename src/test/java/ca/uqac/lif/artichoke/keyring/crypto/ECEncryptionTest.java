package ca.uqac.lif.artichoke.keyring.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Arrays;

import static org.junit.Assert.*;

public class ECEncryptionTest {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testGenerateKeys() {
        KeyPair keyPair0 = ECEncryption.generateNewKeys();
        assertNotNull(keyPair0);

        KeyPair keyPair1 = ECEncryption.generateNewKeys();
        assertNotNull(keyPair1);

        assertFalse(Arrays.equals(keyPair0.getPrivate().getEncoded(), keyPair1.getPrivate().getEncoded()));
        assertFalse(Arrays.equals(keyPair0.getPublic().getEncoded(), keyPair1.getPublic().getEncoded()));
    }

    @Test
    public void testSignature() {
        byte[] data = "data".getBytes();

        ECEncryption ec0 = new ECEncryption();
        ECSignature signature0 = ec0.sign(data);
        assertTrue(ec0.verifySignature(signature0, data));

        KeyPair keyPair = ECEncryption.generateNewKeys();
        ECEncryption ec1 = new ECEncryption(keyPair);
        ECSignature signature1 = ec1.sign(data);
        assertTrue(ec1.verifySignature(signature1, data));

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        ECEncryption ec2 = new ECEncryption(privateKey, publicKey);
        ECSignature signature2 = ec2.sign(data);
        assertTrue(ec2.verifySignature(signature2, data));

        String hexPrivateKey1 = ec1.encodePrivateKey();
        String hexPublicKey2 = ec1.encodePublicKey();

        ECEncryption ec3 = new ECEncryption(hexPrivateKey1, hexPublicKey2);
        ECSignature signature3 = ec3.sign(data);
        assertTrue(ec3.verifySignature(signature3, data));
    }

    @Test
    public void testConvertToAES() {
        for(int i = 0; i < 1000; i++) {
            ECEncryption ec = new ECEncryption();
            SecretKey skey = ec.convertToAESKey();
            assertEquals(32, skey.getEncoded().length);
        }
    }

    @Test
    public void testKeyGetters() {
        KeyPair keyPair = ECEncryption.generateNewKeys();
        ECEncryption ec = new ECEncryption(keyPair);

        assertSame(keyPair.getPrivate(), ec.getPrivateKey());
        assertSame(keyPair.getPublic(), ec.getPublicKey());
    }

    @Test
    public void testDecode()  {
        byte[] data = "data".getBytes();
        for(int i = 0; i < 1000; i++) {
            ECEncryption ecToEncode = new ECEncryption();
            ECSignature signature = ecToEncode.sign(data);

            String hexPrivatekey = ecToEncode.encodePrivateKey();
            String hexPublicKey = ecToEncode.encodePublicKey();

            ECEncryption ecToDecode = new ECEncryption(hexPrivatekey, hexPublicKey);
            assertTrue(ecToDecode.verifySignature(signature.encode(), data));
        }
    }

    @Test
    public void testSignatureFails() {
        byte[] data = "data".getBytes();
        for(int i = 0; i < 100; i++) {
            KeyPair keyPair0 = ECEncryption.generateNewKeys();
            KeyPair keyPair1 = ECEncryption.generateNewKeys();

            ECEncryption ec0 = new ECEncryption(keyPair0);
            ECEncryption ec1 = new ECEncryption(keyPair1);

            ECSignature signature0 = ec0.sign(data);
            ECSignature signature1 = ec1.sign(data);

            assertFalse(ec0.verifySignature(signature1, data));
            assertFalse(ec1.verifySignature(signature0, data));
        }
    }
}