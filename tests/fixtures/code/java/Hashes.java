import java.security.MessageDigest;

public final class Hashes {

    static byte[] md5(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }

    static byte[] sha1(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    static byte[] sha384(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-384").digest(data);
    }

    static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    // MessageDigest.getInstance("MD5") is mentioned in a comment only
    static boolean same(byte[] left, byte[] right) {
        return MessageDigest.isEqual(left, right);
    }
}
