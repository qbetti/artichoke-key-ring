package ca.uqac.lif.artichoke.keyring;

import ca.uqac.lif.artichoke.keyring.crypto.AESEncryption;
import ca.uqac.lif.artichoke.keyring.crypto.ECEncryption;
import ca.uqac.lif.artichoke.keyring.crypto.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


public class MainTest {


    private static final String CURVE_NAME = "secp256k1";

    @Test
    public void ECtest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
//        Security.addProvider(new BouncyCastleProvider());
//
//        ECEncryption ecEncryption = new ECEncryption();
//        ECPrivateKey privateKey = ecEncryption.getPrivateKey();
//        ECPublicKey publicKey = ecEncryption.getPublicKey();
//
//        byte[] s = privateKey.getD().toByteArray();
//        byte[] actualPrivateKey = new byte[32];
//
//        if(s.length >= 32 && s[0] == 0) {
//            actualPrivateKey = Arrays.copyOfRange(s, 1, s.length);
//        } else {
//            actualPrivateKey = s;
//        }
//        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
//        KeyFactory kf = KeyFactory.getInstance("EC", "BC");
//
//        String hexPrivateKey = new String(Hex.encode(actualPrivateKey));
//        String hexPublicKey = new String(Hex.encode(publicKey.getQ().getEncoded(true)));
//
//        String data = "lol";
//        byte[] signature = ecEncryption.sign(data.getBytes());
//
//        boolean result = ecEncryption.verifySignature(signature, data.getBytes());
//
//        System.out.println(result);
//
//        // SCRYPT
//
//        String password = "mdp";
//        SCrypt sCrypt = new SCrypt();
//        byte[] derivedKey = sCrypt.deriveKey(password);
//
//        AESEncryption aesEnc = new AESEncryption(derivedKey);
//        byte[] encryptedPrivateKey = aesEnc.encrypt(actualPrivateKey);
//        String hexEncryptedPrivateKey = new String(Hex.encode(encryptedPrivateKey));
//        System.out.println("HEX crypto private key: " + hexEncryptedPrivateKey);
//        String hexIV = aesEnc.encodeLastIV();
//        System.out.println("IV: " + hexIV);
//
//        byte[] secretKey0 = aesEnc.decrypt(Hex.decode(hexEncryptedPrivateKey), Hex.decode(hexIV));
//        Assert.assertArrayEquals(secretKey0, actualPrivateKey);

//        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(secretKey0), params);
//        PrivateKey sKey = kf.generatePrivate(privateKeySpec);
//
//        Signature ecdsa3 = Signature.getInstance("SHA1withECDSA");
//        ecdsa3.initSign(sKey);
//        ecdsa3.update(data.getBytes());
//        byte[] signature3 = ecdsa3.sign();
//
//        ecdsa3.initVerify(publicKey);
//        ecdsa3.update(data.getBytes());
//
//        boolean result2 = ecdsa3.verify(signature3);
//
//        Assert.assertTrue(result2);
//
//        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
//        generator.init(256);
//        SecretKey secretKey = generator.generateKey();
//        String hexSecretKey = new String(Hex.encode(secretKey.getEncoded()));
//        System.out.println(secretKey.getEncoded().length);
//        System.out.println("hexGroupSecrectKey:" + hexSecretKey);
//
//
//        SecureRandom random1 = new SecureRandom();
//        random1.nextBytes(iv);
//        System.out.println("iv: "+ new String(Hex.encode(iv)));
//
//        Cipher cipher2 = Cipher.getInstance("AES/CTR/NoPadding", "BC");
//        cipher2.init(Cipher.ENCRYPT_MODE, ecEncryption.convertToAESKey(), new IvParameterSpec(iv));
//
//        byte[] encGroupKey = cipher2.doFinal(secretKey.getEncoded());
//        System.out.println(new String(Hex.encode(encGroupKey)));
//
//        cipher2.init(Cipher.DECRYPT_MODE, ecEncryption.convertToAESKey(), new IvParameterSpec(iv));
//        byte[] decGroupKey = cipher2.doFinal(encGroupKey);
//
//        System.out.println("decodedGroupKey:"+ new String(Hex.encode(decGroupKey)));
    }

}