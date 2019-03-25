package ca.uqac.lif.artichoke.keyring;

import ca.uqac.lif.artichoke.keyring.crypto.*;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.SecretKey;
import java.io.*;
import java.util.HashMap;

public class KeyRing {
    public static final String JKEY_SCRYPT_SALT = "salt";
//    public static final String JKEY_SIGNATURE = "signature";
    public static final String JKEY_PUBLIC_KEY = "publicKey";
    public static final String JKEY_PRIVATE_KEY = "privateKey";
    public static final String JKEY_CIPHER_TEXT = "cipherText";
    public static final String JKEY_IV = "iv";
    public static final String JKEY_GROUPS = "groups";
    public static final String JKEY_GROUP_ID = "id";

    private String hexPublicKey;
    private String hexEncryptedPrivateKey;
    private String hexIvPrivateKey;
    private String hexSCryptSalt;
//    private String hexSignature;

    private byte[] derivedKey;
    private HashMap<String, Group> groupsById;


    private KeyRing() {
        this(null);
    }

    private KeyRing(byte[] derivedKey) {
        groupsById = new HashMap<>();
        this.derivedKey = derivedKey;
    }

    /**
     * Package-private
     * @param o
     * @param passphrase
     */
    KeyRing(KeyRing o, String passphrase) {
        this(o, passphrase, true);
    }

    private KeyRing(KeyRing o, String passphrase, boolean stayUnlocked) {
        hexPublicKey = o.hexPublicKey;
        hexEncryptedPrivateKey = o.hexEncryptedPrivateKey;
        hexIvPrivateKey = o.hexIvPrivateKey;
        hexSCryptSalt = o.hexSCryptSalt;
        groupsById = (HashMap<String, Group>) o.groupsById.clone();

        if(stayUnlocked && passphrase == null)
            derivedKey = o.derivedKey.clone();
        else if(stayUnlocked) {
            SCrypt sCrypt = new SCrypt(hexSCryptSalt);
            derivedKey = sCrypt.deriveKey(passphrase);
        }
    }


    public static KeyRing generateNew(String passphrase, boolean stayUnlocked) {
        if(passphrase == null || passphrase.isEmpty())
            return null;

        ECEncryption ec = new ECEncryption();
        SCrypt sCrypt = new SCrypt();

        KeyRing keyRing;
        AESCipher encryptedPrivateKeyCipher;

        if(stayUnlocked) {
            byte[] derivedKey = sCrypt.deriveKey(passphrase);
            keyRing = new KeyRing(derivedKey);
            encryptedPrivateKeyCipher = new AESEncryption(derivedKey).encrypt(ec.getPrivateKeyBytes());
        } else {
            keyRing = new KeyRing();
            encryptedPrivateKeyCipher = sCrypt.encryptWithAES(ec.getPrivateKeyBytes(), passphrase);
        }

        keyRing.hexPublicKey = ec.encodePublicKey();
        keyRing.hexEncryptedPrivateKey = encryptedPrivateKeyCipher.encodeDataBytes();
        keyRing.hexIvPrivateKey = encryptedPrivateKeyCipher.encodeIv();
        keyRing.hexSCryptSalt = sCrypt.encodeSalt();
//        keyRing.hexSignature = ec.sign(keyRing.hexPublicKey).encode();

        return keyRing;
    }


    public static KeyRing loadFromFile(File file) throws IOException {
        return loadFromFile(file, null);
    }


    public static KeyRing loadFromFile(File file, String passphrase) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        String sJKeyRing = br.readLine();
        br.close();

        JsonParser parser = new JsonParser();
        JsonObject jKeyRing = parser.parse(sJKeyRing).getAsJsonObject();

        return fromJson(jKeyRing, passphrase);
    }


    public void saveToFile(File file) throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(file));
        bw.write(this.toJson().toString());
        bw.close();
    }


    public boolean addGroup(String passphrase, String groupId, byte[] groupSecretKey)
            throws BadPassphraseException, GroupIdAlreadyExistsException, EmptyGroupIdException, PrivateKeyDecryptionException {

        SCrypt sCrypt = new SCrypt(hexSCryptSalt);
        return addGroup(sCrypt.deriveKey(passphrase), groupId, groupSecretKey);
    }


    public boolean addGroup(String groupId, byte[] groupSecretKey)
            throws BadPassphraseException, GroupIdAlreadyExistsException, EmptyGroupIdException, PrivateKeyDecryptionException {
        return addGroup(this.derivedKey, groupId, groupSecretKey);
    }


    public boolean addGroup(byte[] derivedKey, String groupId, byte[] groupSecretKey)
            throws PrivateKeyDecryptionException, BadPassphraseException, GroupIdAlreadyExistsException, EmptyGroupIdException {

        if(groupId == null || groupId.isEmpty())
            throw new EmptyGroupIdException();

        if(groupsById.containsKey(groupId))
            throw new GroupIdAlreadyExistsException(groupId);

        AESEncryption aes = initAESEncryption(derivedKey);
        AESCipher groupKeyCipher = aes.encrypt(groupSecretKey);
        if(groupKeyCipher == null)
            return false;

        groupsById.put(groupId, new Group(groupId, groupKeyCipher.encodeDataBytes(), groupKeyCipher.encodeIv()));
        return true;
    }


    public byte[] retrieveGroupKey(String passphrase, String groupId)
            throws PrivateKeyDecryptionException, BadPassphraseException, NonExistingGroupIdException {

        SCrypt sCrypt = new SCrypt(hexSCryptSalt);
        return retrieveGroupKey(sCrypt.deriveKey(passphrase), groupId);
    }


    public byte[] retrieveGroupKey(String groupId)
            throws PrivateKeyDecryptionException, NonExistingGroupIdException, BadPassphraseException {

        return retrieveGroupKey(this.derivedKey, groupId);
    }


    public byte[] retrieveGroupKey(byte[] derivedKey, String groupId)
            throws PrivateKeyDecryptionException, BadPassphraseException, NonExistingGroupIdException {

        Group group = groupsById.get(groupId);
        if(group == null)
            throw new NonExistingGroupIdException(groupId);

        AESEncryption aes = initAESEncryption(derivedKey);
        AESCipher cipher = aes.decrypt(group.getHexEncryptedSecretKey(), group.getHexIvSecretKey());
        if(cipher == null)
            return null;

        return cipher.getDataBytes();
    }


    private AESEncryption initAESEncryption(byte[] derivedKey)
            throws PrivateKeyDecryptionException, BadPassphraseException {

        byte[] ecPrivateKey = decryptECPrivateKey(derivedKey);
        SecretKey secretKey = AESEncryption.convertToAESKey(ecPrivateKey);
        return new AESEncryption(secretKey);
    }


    private byte[] decryptECPrivateKey(byte[] derivedKey)
            throws BadPassphraseException, PrivateKeyDecryptionException {

        AESCipher ecPrivateKeyCipher = new AESEncryption(derivedKey).decrypt(hexEncryptedPrivateKey, hexIvPrivateKey);
        if(ecPrivateKeyCipher == null)
            throw new PrivateKeyDecryptionException();

        byte[] privateKey = ecPrivateKeyCipher.getDataBytes();

        if(verifyPrivateKey(privateKey))
            return privateKey;
        else
            throw new BadPassphraseException();
    }


    private boolean verifyPrivateKey(byte[] ecPrivateKey) {
        ECEncryption ec = new ECEncryption(ecPrivateKey, hexPublicKey);
        ECSignature signature = ec.sign(hexPublicKey);
        return ec.verifySignature(signature, hexPublicKey);
    }


    public JsonObject toJson() {
        JsonObject jKeyRing = new JsonObject();

        jKeyRing.addProperty(JKEY_SCRYPT_SALT, hexSCryptSalt);
//        jKeyRing.addProperty(JKEY_SIGNATURE, hexSignature);

        jKeyRing.addProperty(JKEY_PUBLIC_KEY, hexPublicKey);

        JsonObject jPrivateKey = new JsonObject();
        jPrivateKey.addProperty(JKEY_CIPHER_TEXT, hexEncryptedPrivateKey);
        jPrivateKey.addProperty(JKEY_IV, hexIvPrivateKey);
        jKeyRing.add(JKEY_PRIVATE_KEY, jPrivateKey);

        JsonArray jGroups = new JsonArray();
        for(Group group : groupsById.values()) {
            JsonObject jGroup = new JsonObject();
            jGroup.addProperty(JKEY_GROUP_ID, group.getId());
            jGroup.addProperty(JKEY_CIPHER_TEXT, group.getHexEncryptedSecretKey());
            jGroup.addProperty(JKEY_IV, group.getHexIvSecretKey());

            jGroups.add(jGroup);
        }
        jKeyRing.add(JKEY_GROUPS, jGroups);

        return jKeyRing;
    }


    public static KeyRing fromJson(JsonObject jKeyRing) {
        return fromJson(jKeyRing, null);
    }


    public static KeyRing fromJson(JsonObject jKeyRing, String passphrase) {
        KeyRing keyRing = new KeyRing();
        keyRing.hexSCryptSalt = jKeyRing.get(JKEY_SCRYPT_SALT).getAsString();
        keyRing.hexPublicKey = jKeyRing.get(JKEY_PUBLIC_KEY).getAsString();

        JsonObject jPrivateKey = jKeyRing.getAsJsonObject(JKEY_PRIVATE_KEY);

        keyRing.hexEncryptedPrivateKey = jPrivateKey.get(JKEY_CIPHER_TEXT).getAsString();
        keyRing.hexIvPrivateKey = jPrivateKey.get(JKEY_IV).getAsString();

        JsonArray jGroups = jKeyRing.getAsJsonArray(JKEY_GROUPS);
        for (JsonElement e : jGroups) {
            JsonObject jGroup = e.getAsJsonObject();
            Group group = new Group(
                    jGroup.get(JKEY_GROUP_ID).getAsString(),
                    jGroup.get(JKEY_CIPHER_TEXT).getAsString(),
                    jGroup.get(JKEY_IV).getAsString()
            );
            keyRing.groupsById.put(group.getId(), group);
        }

        if(passphrase != null) {
            SCrypt sCrypt = new SCrypt(keyRing.hexSCryptSalt);
            keyRing.derivedKey = sCrypt.deriveKey(passphrase);
        }
        return keyRing;
    }
}
