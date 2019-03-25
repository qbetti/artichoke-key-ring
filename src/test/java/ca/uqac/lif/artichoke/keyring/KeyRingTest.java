package ca.uqac.lif.artichoke.keyring;

import ca.uqac.lif.artichoke.keyring.crypto.AESEncryption;
import com.google.gson.JsonObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.Security;

import static org.junit.Assert.*;

public class KeyRingTest {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testJson() {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);

        SecretKey group0Key = AESEncryption.generateNewKey();
        keyRing.addGroup("test", group0Key.getEncoded());

        SecretKey group1Key = AESEncryption.generateNewKey();
        keyRing.addGroup( "test1", group1Key.getEncoded());

        JsonObject jKeyRing = keyRing.toJson();

        KeyRing o = KeyRing.fromJson(jKeyRing);
        JsonObject jO = o.toJson();

        assertEquals(jKeyRing, jO);
        System.out.println(jKeyRing);
        System.out.println(jO);
    }


    @Test
    public void testGroupManagement() {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);

        SecretKey group0Key = AESEncryption.generateNewKey();
        assertTrue(keyRing.addGroup( "group0", group0Key.getEncoded()));
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey(passphrase, "group0"));

        SecretKey group1Key = AESEncryption.generateNewKey();
        assertFalse(keyRing.addGroup( "group0", group0Key.getEncoded()));
        assertNull(keyRing.retrieveGroupKey( "group1"));

        // Tests with wrong passphrase
        String wrongPassphrase = "wrongPassphrase";
        KeyRing keyRingWithWrongPassphrase = new KeyRing(keyRing, wrongPassphrase);

        assertFalse(keyRingWithWrongPassphrase.addGroup( "group1", group1Key.getEncoded()));
        assertNull(keyRingWithWrongPassphrase.retrieveGroupKey( "group0"));
    }

    @Test
    public void testStayLocked() {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, false);

        SecretKey group0Key = AESEncryption.generateNewKey();

        assertTrue(keyRing.addGroup(passphrase, "group0", group0Key.getEncoded()));
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey(passphrase, "group0"));
    }

    @Test
    public void testStayUnlocked() {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);

        SecretKey group0Key = AESEncryption.generateNewKey();

        assertTrue(keyRing.addGroup( "group0", group0Key.getEncoded()));
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey("group0"));
    }

    @Test
    public void testSaveLoad() {
        try {
            String passphrase = "passphrase";
            KeyRing keyRing = KeyRing.generateNew(passphrase, true);

            SecretKey group0Key = AESEncryption.generateNewKey();
            keyRing.addGroup("test", group0Key.getEncoded());

            SecretKey group1Key = AESEncryption.generateNewKey();
            keyRing.addGroup( "test1", group1Key.getEncoded());

            keyRing.saveToFile(new File("keyring.json"));

            KeyRing o = KeyRing.loadFromFile(new File("keyring.json"));
            assertEquals(keyRing.toJson(), o.toJson());

        } catch (IOException e) {
            e.printStackTrace();
            fail();
        }
    }
}