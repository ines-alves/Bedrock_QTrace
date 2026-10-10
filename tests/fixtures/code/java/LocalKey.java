import java.nio.charset.StandardCharsets;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public final class LocalKey {

    public static byte[] local(byte[] data) throws Exception {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data);
    }

    public static byte[] sink(byte[] key, byte[] data) throws Exception {
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data);
    }

    public static byte[] caller(byte[] data) throws Exception {
        byte[] secret = "fedcba9876543210fedcba9876543210".getBytes(StandardCharsets.UTF_8);
        return sink(secret, data);
    }

    public static byte[] reassigned(byte[] other, byte[] data) throws Exception {
        byte[] key = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        key = other;
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(data);
    }

    public static byte[] literalIsPlaintext(byte[] key) throws Exception {
        byte[] payload = "4111-1111-1111-1111".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec spec = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, spec);
        return cipher.doFinal(payload);
    }
}
