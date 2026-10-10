import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public final class Ciphers {

    private static final byte[] FIXED_KEY = "0123456789ABCDEF".getBytes();
    private static final String ECB_TRANSFORM = "AES/ECB/PKCS5Padding";
    private static final String GCM_TRANSFORM = "AES/GCM/NoPadding";
    private static final int KEY_BITS = 256;

    static byte[] ecbFromConstants(byte[] data) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(FIXED_KEY, "AES");
        Cipher cipher = Cipher.getInstance(ECB_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data);
    }

    static SecretKey newKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_BITS);
        return generator.generateKey();
    }

    static byte[] gcm(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(GCM_TRANSFORM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    static byte[] literalGcm(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    static byte[] bareAes(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    static byte[] customProvider(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    static byte[] cbcWithImportedKey(SecretKey importedKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, importedKey);
        return cipher.doFinal(data);
    }

    static byte[] rsaOaep(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    static byte[] run(byte[] data) throws Exception {
        SecretKey key = newKey();
        byte[] first = gcm(key, data);
        return literalGcm(key, first);
    }
}
