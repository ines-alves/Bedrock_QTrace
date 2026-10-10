import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import javax.crypto.spec.SecretKeySpec;

public final class HardcodedKeys {

    private static final byte[] CONST_KEY = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
    private static final byte[] MAC_KEY = "shared-signing-key-32-bytes-long".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SHADOW_KEY = "shadowed-key-0123".getBytes(StandardCharsets.UTF_8);
    private static final byte[] SALT = "fixed-salt-value".getBytes(StandardCharsets.UTF_8);

    static SecretKeySpec fromConstant() {
        return new SecretKeySpec(CONST_KEY, "AES");
    }

    static SecretKeySpec inline() {
        return new SecretKeySpec("fedcba9876543210".getBytes(), "AES");
    }

    static SecretKeySpec forMac() {
        return new SecretKeySpec(MAC_KEY, "HmacSHA256");
    }

    static SecretKeySpec salt() {
        return new SecretKeySpec(SALT, "PBKDF2");
    }

    static SecretKeySpec random() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    static SecretKeySpec imported(byte[] key) {
        return new SecretKeySpec(key, "AES");
    }

    static SecretKeySpec shadowed(byte[] SHADOW_KEY) {
        return new SecretKeySpec(SHADOW_KEY, "AES");
    }
}
