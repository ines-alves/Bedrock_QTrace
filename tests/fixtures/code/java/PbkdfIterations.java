import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PbkdfIterations {
    private static final int ITERATIONS = 600_000;

    byte[] literal(char[] password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, 10000, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(spec).getEncoded();
    }

    byte[] constant(char[] password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    byte[] computed(char[] password, byte[] salt, int base) throws Exception {
        int rounds = base * 2;
        KeySpec spec = new PBEKeySpec(password, salt, rounds, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    byte[] parameter(char[] password, byte[] salt, int rounds) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, rounds, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512").generateSecret(spec).getEncoded();
    }

    byte[] caller(char[] password, byte[] salt) throws Exception {
        return parameter(password, salt, 65536);
    }

    byte[] two_specs(char[] password, byte[] salt) throws Exception {
        KeySpec first = new PBEKeySpec(password, salt, 1000, 256);
        KeySpec second = new PBEKeySpec(password, salt, 600_000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(first).getEncoded();
    }

    byte[] without_length(char[] password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password, salt, 4096);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
