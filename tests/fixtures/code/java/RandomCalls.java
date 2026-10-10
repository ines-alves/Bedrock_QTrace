import java.security.SecureRandom;
import java.util.Random;

public final class RandomCalls {

    static byte[] weak() {
        byte[] token = new byte[16];
        new Random().nextBytes(token);
        return token;
    }

    static byte[] strong() {
        byte[] token = new byte[16];
        new SecureRandom().nextBytes(token);
        return token;
    }
}
