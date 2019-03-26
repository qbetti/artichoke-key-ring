package ca.uqac.lif.artichoke.keyring;

import ca.uqac.lif.artichoke.keyring.crypto.AESEncryption;
import ca.uqac.lif.artichoke.keyring.exceptions.*;
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
    public void testJson() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
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
    }

    @Test
    public void testGroupManagement() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);

        SecretKey group0Key = AESEncryption.generateNewKey();
        // Test add group
        assertTrue(keyRing.addGroup( "group0", group0Key.getEncoded()));
        // Test retrieve group
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey(passphrase, "group0"));
    }

    @Test(expected = NonExistingGroupIdException.class)
    public void testRetrieveNonExistingGroup() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);
        keyRing.retrieveGroupKey( "group0");
    }

    @Test(expected = DuplicatedGroupIdException.class)
    public void testAddAlreadyExistingGroup() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);
        SecretKey group0Key = AESEncryption.generateNewKey();
        keyRing.addGroup( "group0", group0Key.getEncoded());
        keyRing.addGroup("group0", group0Key.getEncoded());
    }

    @Test(expected = BadPassphraseException.class)
    public void testAddWithWrongPassphrase() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        String wrongPassphrase = "wrongPassphrase";

        KeyRing keyRing = KeyRing.generateNew(passphrase, false);
        SecretKey group0Key = AESEncryption.generateNewKey();
        keyRing.addGroup( wrongPassphrase, "group0", group0Key.getEncoded());
    }

    @Test(expected = BadPassphraseException.class)
    public void testRetrieveWithWrongPassphrase() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        String wrongPassphrase = "wrongPassphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);

        SecretKey group0Key = AESEncryption.generateNewKey();
        keyRing.addGroup( "group0", group0Key.getEncoded());
        keyRing.retrieveGroupKey(wrongPassphrase, "group0");
    }

    @Test
    public void testStayLocked() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, false);

        SecretKey group0Key = AESEncryption.generateNewKey();

        assertTrue(keyRing.addGroup(passphrase, "group0", group0Key.getEncoded()));
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey(passphrase, "group0"));
    }

    @Test
    public void testStayUnlocked() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);

        SecretKey group0Key = AESEncryption.generateNewKey();

        assertTrue(keyRing.addGroup( "group0", group0Key.getEncoded()));
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey("group0"));
    }

    @Test
    public void testSaveLoad() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException, IOException {
        String passphrase = "passphrase";
        KeyRing keyRing = KeyRing.generateNew(passphrase, true);

        SecretKey group0Key = AESEncryption.generateNewKey();
        keyRing.addGroup("test", group0Key.getEncoded());

        SecretKey group1Key = AESEncryption.generateNewKey();
        keyRing.addGroup( "test1", group1Key.getEncoded());

        keyRing.saveToFile(new File("keyring.json"));

        KeyRing o = KeyRing.loadFromFile(new File("keyring.json"));
        assertEquals(keyRing.toJson(), o.toJson());
    }

    @Test
    public void testVerifyPassphrase() throws PrivateKeyDecryptionException {
        String passphrase = "passphrase";
        String wrongPassphrase = "wrongPassphrase";

        KeyRing keyRing = KeyRing.generateNew(passphrase, true);
        assertTrue(keyRing.verifyPassphrase());
        assertTrue(keyRing.verifyPassphrase(passphrase));
        assertFalse(keyRing.verifyPassphrase(wrongPassphrase));

        keyRing = KeyRing.generateNew(passphrase, false);
        assertFalse(keyRing.verifyPassphrase());
        assertTrue(keyRing.verifyPassphrase(passphrase));
        assertFalse(keyRing.verifyPassphrase(wrongPassphrase));
    }
}