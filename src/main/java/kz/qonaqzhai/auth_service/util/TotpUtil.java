package kz.qonaqzhai.auth_service.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public final class TotpUtil {

    private static final String HMAC_ALGORITHM = "HmacSHA1";
    private static final int DEFAULT_DIGITS = 6;
    private static final int DEFAULT_PERIOD_SECONDS = 30;

    private static final char[] BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] BASE32_LOOKUP = new int[128];

    static {
        for (int i = 0; i < BASE32_LOOKUP.length; i++) {
            BASE32_LOOKUP[i] = -1;
        }
        for (int i = 0; i < BASE32_ALPHABET.length; i++) {
            BASE32_LOOKUP[BASE32_ALPHABET[i]] = i;
        }
    }

    private TotpUtil() {}

    public static String generateBase32Secret(int numBytes) {
        byte[] bytes = new byte[numBytes];
        new SecureRandom().nextBytes(bytes);
        return base32Encode(bytes);
    }

    public static boolean verifyCode(String base32Secret, String code) {
        if (base32Secret == null || base32Secret.isBlank()) return false;
        if (code == null) return false;

        String normalized = code.replaceAll("\\s+", "").trim();
        if (!normalized.matches("\\d{6}")) return false;

        long nowSeconds = System.currentTimeMillis() / 1000L;
        long counter = nowSeconds / DEFAULT_PERIOD_SECONDS;

        // allow +/- 1 step clock skew
        for (long c = counter - 1; c <= counter + 1; c++) {
            String expected = generateTotp(base32Secret, c, DEFAULT_DIGITS);
            if (normalized.equals(expected)) return true;
        }

        return false;
    }

    private static String generateTotp(String base32Secret, long counter, int digits) {
        byte[] key = base32Decode(base32Secret);
        byte[] data = ByteBuffer.allocate(8).putLong(counter).array();

        byte[] hash = hmacSha1(key, data);

        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

        int otp = binary % (int) Math.pow(10, digits);
        return String.format("%0" + digits + "d", otp);
    }

    private static byte[] hmacSha1(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new IllegalStateException("Unable to generate TOTP", e);
        }
    }

    private static String base32Encode(byte[] data) {
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);

        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer <<= 8;
            buffer |= (b & 0xFF);
            bitsLeft += 8;

            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                bitsLeft -= 5;
                out.append(BASE32_ALPHABET[index]);
            }
        }

        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            out.append(BASE32_ALPHABET[index]);
        }

        return out.toString();
    }

    private static byte[] base32Decode(String base32) {
        if (base32 == null) return new byte[0];

        String s = base32.replace("=", "").replaceAll("\\s+", "").toUpperCase();

        ByteBuffer out = ByteBuffer.allocate((s.length() * 5) / 8 + 1);

        int buffer = 0;
        int bitsLeft = 0;

        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= BASE32_LOOKUP.length) continue;

            int val = BASE32_LOOKUP[ch];
            if (val < 0) continue;

            buffer <<= 5;
            buffer |= val;
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                int b = (buffer >> (bitsLeft - 8)) & 0xFF;
                bitsLeft -= 8;
                out.put((byte) b);
            }
        }

        out.flip();
        byte[] bytes = new byte[out.remaining()];
        out.get(bytes);
        return bytes;
    }
}
