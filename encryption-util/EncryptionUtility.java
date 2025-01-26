import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class EncryptionUtility {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String AES_ALGORITHM = "AES";
    private static final String DES_ALGORITHM = "DES";
    private static final String DES_EDE_ALGORITHM = "DESede"; // 3DES
    private static final String BLOWFISH_ALGORITHM = "Blowfish";
    private static final String RC2_ALGORITHM = "RC2";
    private static final String CHACHA20_ALGORITHM = "ChaCha20";
    private static final String CHACHA20_POLY1305_ALGORITHM = "ChaCha20-Poly1305";
    
    private String encryptionAlgorithm;
    private String mode;
    private String padding;
    private String cipherTransformation;

    public EncryptionUtility(String algorithm, String mode, String padding) {
        this.encryptionAlgorithm = algorithm;
        this.mode = mode;
        this.padding = padding;
        
        // Handle special cases for cipher transformations
        if (CHACHA20_ALGORITHM.equals(algorithm) || CHACHA20_POLY1305_ALGORITHM.equals(algorithm)) {
            this.cipherTransformation = algorithm;
            this.mode = "";
            this.padding = "";
        } else {
            this.cipherTransformation = algorithm + "/" + mode + "/" + padding;
        }
    }

    private void validateKeyLength(byte[] key) {
        int length = key.length * 8; // Convert byte length to bit length
        switch (encryptionAlgorithm) {
            case AES_ALGORITHM:
                if (length != 128 && length != 192 && length != 256) {
                    throw new IllegalArgumentException("Invalid AES key length: " + length + " bits. Key must be 128, 192, or 256 bits.");
                }
                break;
            case DES_ALGORITHM:
                if (length != 64) { // 64 bits = 8 bytes (56-bit effective)
                    throw new IllegalArgumentException("Invalid DES key length: " + length + " bits. Key must be 64 bits (8 bytes) including parity.");
                }
                break;
            case DES_EDE_ALGORITHM:
                if (length != 128 && length != 192) { // 128/192 bits (16/24 bytes)
                    throw new IllegalArgumentException("Invalid 3DES key length: " + length + " bits. Key must be 128 or 192 bits (16/24 bytes).");
                }
                break;
            case BLOWFISH_ALGORITHM:
                if (length < 32 || length > 448 || (length % 8) != 0) {
                    throw new IllegalArgumentException("Invalid Blowfish key length: " + length + " bits. Key must be 32-448 bits in 8-bit increments.");
                }
                break;
            case RC2_ALGORITHM:
                if (length < 8 || length > 1024 || (length % 8) != 0) {
                    throw new IllegalArgumentException("Invalid RC2 key length: " + length + " bits. Key must be 8-1024 bits in 8-bit increments.");
                }
                break;
            case CHACHA20_ALGORITHM:
            case CHACHA20_POLY1305_ALGORITHM:
                if (length != 256) {
                    throw new IllegalArgumentException("Invalid ChaCha20 key length: " + length + " bits. Key must be 256 bits.");
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + encryptionAlgorithm);
        }
    }

    private void validateIVLength(byte[] iv) {
        if (!requiresIV()) return;

        switch (encryptionAlgorithm) {
            case AES_ALGORITHM:
                if ("GCM".equals(mode)) {
                    if (iv.length != 12) {
                        throw new IllegalArgumentException("IV for AES/GCM must be 12 bytes.");
                    }
                } else if (iv.length != 16) {
                    throw new IllegalArgumentException("IV for AES/" + mode + " must be 16 bytes.");
                }
                break;
            case DES_ALGORITHM:
            case DES_EDE_ALGORITHM:
                if (iv.length != 8) {
                    throw new IllegalArgumentException("IV for " + encryptionAlgorithm + "/" + mode + " must be 8 bytes.");
                }
                break;
            case BLOWFISH_ALGORITHM:
                if (iv.length != 8) {
                    throw new IllegalArgumentException("IV for Blowfish/" + mode + " must be 8 bytes.");
                }
                break;
            case RC2_ALGORITHM:
                if (iv.length != 8) {
                    throw new IllegalArgumentException("IV for " + encryptionAlgorithm + "/" + mode + " must be 8 bytes.");
                }
                break;
            case CHACHA20_ALGORITHM:
            case CHACHA20_POLY1305_ALGORITHM:
                if (iv.length != 12) {
                    throw new IllegalArgumentException("IV for " + encryptionAlgorithm + " must be 12 bytes.");
                }
                break;
            default:
                throw new IllegalArgumentException("Unsupported algorithm for IV validation: " + encryptionAlgorithm);
        }
    }

    private boolean requiresIV() {
        return !"ECB".equals(mode);
    }

    public byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv) throws Exception {
        validateKeyLength(key);
        if (requiresIV()) {
            validateIVLength(iv);
        }

        Cipher cipher = Cipher.getInstance(cipherTransformation, "BC");
        if (requiresIV()) {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, encryptionAlgorithm), new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, encryptionAlgorithm));
        }
        return cipher.doFinal(cipherText);
    }

    public String decrypt1(String cipherText, String key, String iv, String inputFormat, String keyFormat, String ivFormat) {
        try {
            byte[] cipherBytes = decodeInput(cipherText, inputFormat);
            byte[] keyBytes = decodeInput(key, keyFormat);
            byte[] ivBytes = requiresIV() ? decodeInput(iv, ivFormat) : new byte[0];
            
            byte[] decryptedBytes = decrypt(cipherBytes, keyBytes, ivBytes);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    public byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) throws Exception {
        validateKeyLength(key);
        if (requiresIV()) {
            validateIVLength(iv);
        }

        checkBlockAlignment(plainText);

        Cipher cipher = Cipher.getInstance(cipherTransformation, "BC");
        if (requiresIV()) {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, encryptionAlgorithm), new IvParameterSpec(iv));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, encryptionAlgorithm));
        }
        return cipher.doFinal(plainText);
    }

    private void checkBlockAlignment(byte[] data) {
        if ("NoPadding".equals(padding)) {
            int blockSize = getBlockSize();
            if (data.length % blockSize != 0) {
                throw new IllegalArgumentException("Data length must be multiple of " + blockSize + " bytes for " + encryptionAlgorithm + " with NoPadding.");
            }
        }
    }

    private int getBlockSize() {
        switch (encryptionAlgorithm) {
            case AES_ALGORITHM:
                return 16;
            case DES_ALGORITHM:
            case DES_EDE_ALGORITHM:
            case BLOWFISH_ALGORITHM:
            case RC2_ALGORITHM:
                return 8;
            case CHACHA20_ALGORITHM:
            case CHACHA20_POLY1305_ALGORITHM:
                return 64; // ChaCha20 is a stream cipher; block size not applicable
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + encryptionAlgorithm);
        }
    }

    public String encrypt1(String plainText, String key, String iv, String outputFormat, String keyFormat, String ivFormat) {
        try {
            byte[] plainTextBytes = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] keyBytes = decodeInput(key, keyFormat);
            byte[] ivBytes = requiresIV() ? decodeInput(iv, ivFormat) : new byte[0];
            
            byte[] encryptedBytes = encrypt(plainTextBytes, keyBytes, ivBytes);
            return encodeOutput(encryptedBytes, outputFormat);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private byte[] decodeInput(String input, String format) {
        switch (format.toLowerCase()) {
            case "hex":
                return hexToBytes(input);
            case "base64":
                return Base64.getDecoder().decode(input);
            case "plain":
                return input.getBytes(StandardCharsets.UTF_8);
            default:
                throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    private String encodeOutput(byte[] output, String format) {
        switch (format.toLowerCase()) {
            case "hex":
                return bytesToHex(output);
            case "base64":
                return Base64.getEncoder().encodeToString(output);
            case "plain":
                return new String(output, StandardCharsets.UTF_8);
            default:
                throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private byte[] hexToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        if (args.length != 10) {
            System.out.println("Usage: java -jar EncryptionUtility.jar <enc|dec> <algorithm> <data> <key> <iv> <mode> <padding> <keyFormat> <ivFormat> <format>");
            System.out.println("Available algorithms: AES, DES, DESede, Blowfish, RC2, ChaCha20, ChaCha20-Poly1305");
            System.out.println("Available modes: ECB, CBC, CFB, OFB, GCM");
            System.out.println("Available paddings: NoPadding, PKCS5Padding, PKCS7Padding");
            System.out.println("Available formats: base64, hex, plain");
            return;
        }

        String operation = args[0];
        String algorithm = args[1];
        String data = args[2];
        String key = args[3];
        String iv = args[4];
        String mode = args[5];
        String padding = args[6];
        String keyFormat = args[7];
        String ivFormat = args[8];
        String format = args[9];

        EncryptionUtility util = new EncryptionUtility(algorithm, mode, padding);
        String result = "";

        switch (operation) {
            case "enc":
                result = util.encrypt1(data, key, iv, format, keyFormat, ivFormat);
                break;
            case "dec":
                result = util.decrypt1(data, key, iv, format, keyFormat, ivFormat);
                break;
            default:
                System.out.println("Error: Invalid operation. Use 'enc' or 'dec'.");
                return;
        }

        System.out.println(result);
    }
}