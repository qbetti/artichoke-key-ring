package ca.uqac.lif.artichoke.keyring.json;

import ca.uqac.lif.artichoke.keyring.HexString;
import ca.uqac.lif.artichoke.keyring.crypto.AESCipher;
import ca.uqac.lif.artichoke.keyring.crypto.AESEncryption;
import ca.uqac.lif.artichoke.keyring.crypto.ECEncryption;
import ca.uqac.lif.artichoke.keyring.crypto.SCrypt;
import com.google.gson.Gson;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.security.Security;

public class KeyRingJsonTest {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    private KeyRingJson buildKeyRingJson() {
        String passphrase = "passphrase";

        ECEncryption ec = new ECEncryption();
        SCrypt sc = new SCrypt();
        AESCipher privateKeyCipher = sc.encryptWithAES(ec.getPrivateKeyBytes(), passphrase);
        System.out.println("PublicKey: " + ec.encodePublicKey());
        System.out.println("PrivateKey: " + ec.encodePrivateKey());

        AESEncryption ecAes = new AESEncryption(ec.convertToAESKey());

        SecretKey aesKeyGroup0 = AESEncryption.generateNewKey();
        AESCipher group0AesKeyCipher = ecAes.encrypt(aesKeyGroup0.getEncoded());

        SecretKey aesKeyGroup1 = AESEncryption.generateNewKey();
        AESCipher group1AesKeyCipher = ecAes.encrypt(aesKeyGroup1.getEncoded());

        KeyRingJson keyRingJson = new KeyRingJson();
        keyRingJson.setPublicKey(ec.encodePublicKey());

        PrivateKeyJson privateKeyJson = new PrivateKeyJson();
        privateKeyJson.setCipher(privateKeyCipher.encodeDataBytes());
        privateKeyJson.setIv(privateKeyCipher.encodeIv());
        keyRingJson.setPrivateKey(privateKeyJson);

        keyRingJson.setSalt(sc.encodeSalt());

        GroupJson group0Json = new GroupJson();
        group0Json.setId("group0");
        PrivateKeyJson group0SecretKey = new PrivateKeyJson();
        group0SecretKey.setCipher(group0AesKeyCipher.encodeDataBytes());
        group0SecretKey.setIv(group0AesKeyCipher.encodeIv());
        group0Json.setSecretKey(group0SecretKey);
        keyRingJson.getGroups().add(group0Json);
        System.out.println("group0: " + HexString.encode(aesKeyGroup0.getEncoded()));

        GroupJson group1Json = new GroupJson();
        group1Json.setId("group1");
        PrivateKeyJson group1SecretKey = new PrivateKeyJson();
        group1SecretKey.setCipher(group1AesKeyCipher.encodeDataBytes());
        group1SecretKey.setIv(group1AesKeyCipher.encodeIv());
        group1Json.setSecretKey(group1SecretKey);
        keyRingJson.getGroups().add(group1Json);
        System.out.println("group1: " + HexString.encode(aesKeyGroup1.getEncoded()));


        return keyRingJson;
    }

    @Test
    public void testBuildAndWriteJson() {
        KeyRingJson keyRingJson = buildKeyRingJson();
        Gson gson = new Gson();

        System.out.println(gson.toJson(keyRingJson));

        SCrypt sc = new SCrypt(keyRingJson.getSalt());
        AESCipher privateKeyCipher = sc.decryptWithAES(
                keyRingJson.getPrivateKey().getCipher(),
                keyRingJson.getPrivateKey().getIv(),
                "passphrase");

        System.out.println("PublicKey: " + keyRingJson.getPublicKey());
        System.out.println("PrivateKey: " + privateKeyCipher.encodeDataBytes());

        AESEncryption aes = new AESEncryption(privateKeyCipher.getDataBytes());
        AESCipher group0Cipher = aes.decrypt(
                keyRingJson.getGroups().get(0).getSecretKey().getCipher(),
                keyRingJson.getGroups().get(0).getSecretKey().getIv()
        );
        AESCipher group1Cipher = aes.decrypt(
                keyRingJson.getGroups().get(1).getSecretKey().getCipher(),
                keyRingJson.getGroups().get(1).getSecretKey().getIv()
        );

        System.out.println("group0: "+ group0Cipher.encodeDataBytes());
        System.out.println("group1: "+ group1Cipher.encodeDataBytes());

    }
}
