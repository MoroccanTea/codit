package com.acme.crypto;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

@Component
public class TokenCipher {

    // codit-expect: CWE-321 AES key hard-coded in the source
    private static final byte[] LEGACY_KEY = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);



    private final SecretKey dataKey;
    private final SecureRandom random = new SecureRandom();

    public TokenCipher(KmsClient kms) {
        // codit-safe: CWE-321 data key unwrapped from the KMS at start-up, never stored in code
        this.dataKey = new SecretKeySpec(kms.decryptDataKey(System.getenv("TOKEN_DATA_KEY_BLOB")), "AES");
    }

    public String encryptLegacy(String plain) throws Exception {
        // codit-expect: CWE-327 AES in ECB mode leaks plaintext patterns
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(LEGACY_KEY, "AES"));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
    }

    public String encryptCbcLegacy(String plain) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // codit-expect: CWE-321 all-zero IV reused for every message
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(LEGACY_KEY, "AES"), new IvParameterSpec(new byte[16]));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
    }

    public String encryptDes(String plain) throws Exception {
        // codit-expect: CWE-327 single DES (56-bit key) is broken
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(LEGACY_KEY, 0, 8, "DES"));
        return Base64.getEncoder().encodeToString(cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
    }

    public String encrypt(String plain) throws Exception {
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        // codit-safe: CWE-327 AES-GCM with a fresh random 96-bit nonce per message
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, dataKey, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(ct, 0, out, iv.length, ct.length);
        return Base64.getEncoder().encodeToString(out);
    }

    public KeyPair legacySigningKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        // codit-expect: CWE-326 1024-bit RSA key
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }



    public KeyPair signingKeys() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        // codit-safe: CWE-326 3072-bit RSA key
        kpg.initialize(3072);
        return kpg.generateKeyPair();
    }

    public byte[] legacyChecksum(byte[] payload) throws NoSuchAlgorithmException {
        // codit-expect: CWE-327 MD5 used to sign webhook payloads
        return MessageDigest.getInstance("MD5").digest(payload);
    }



    public byte[] checksum(byte[] payload) throws NoSuchAlgorithmException {
        // codit-safe: CWE-327 SHA-256 digest
        return MessageDigest.getInstance("SHA-256").digest(payload);
    }

    public interface KmsClient {
        byte[] decryptDataKey(String blob);
    }
}
