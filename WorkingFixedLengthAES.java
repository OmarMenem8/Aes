import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class WorkingFixedLengthAES {
    
    // Stores full ciphertexts for later decryption
    private static Map<String, String> ciphertextStore = new HashMap<>();
    
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("=== Fixed-Length AES Encryption (Working) ===");
        
        // Fixed IV for demonstration
        byte[] iv = new byte[16];
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        while (true) {
            System.out.println("\n1. Encrypt a message");
            System.out.println("2. Decrypt a message");
            System.out.println("3. Exit");
            System.out.print("Choose an option (1-3): ");
            
            int choice = scanner.nextInt();
            scanner.nextLine(); // Consume newline
            
            switch (choice) {
                case 1:
                    handleEncryption(scanner, ivSpec);
                    break;
                case 2:
                    handleDecryption(scanner, ivSpec);
                    break;
                case 3:
                    System.out.println("Exiting program...");
                    System.exit(0);
                default:
                    System.out.println("Invalid choice!");
            }
        }
    }
    
    private static void handleEncryption(Scanner scanner, IvParameterSpec ivSpec) throws Exception {
        System.out.print("Enter shift key (1-25): ");
        int shiftKey = scanner.nextInt();
        scanner.nextLine();
        System.out.print("Enter message to encrypt: ");
        String plaintext = scanner.nextLine();
        
        // Real AES encryption
        SecretKeySpec secretKey = generateKeyFromShift(shiftKey);
        String fullCipher = realEncrypt(plaintext, secretKey, ivSpec);
        
        // Create fixed-length representation
        String displayCipher = createFixedLengthDisplay(fullCipher, plaintext.length());
        
        // Store mapping for decryption
        ciphertextStore.put(displayCipher, fullCipher);
        
        System.out.println("Encrypted message: " + displayCipher);
    }
    
    private static void handleDecryption(Scanner scanner, IvParameterSpec ivSpec) throws Exception {
        System.out.print("Enter shift key (1-25): ");
        int shiftKey = scanner.nextInt();
        scanner.nextLine();
        System.out.print("Enter encrypted message: ");
        String displayCipher = scanner.nextLine();
        
        // Get real ciphertext from storage
        String fullCipher = ciphertextStore.get(displayCipher);
        if (fullCipher == null) {
            System.out.println("Error: No matching ciphertext found");
            return;
        }
        
        // Real decryption
        SecretKeySpec secretKey = generateKeyFromShift(shiftKey);
        String decrypted = realDecrypt(fullCipher, secretKey, ivSpec);
        
        System.out.println("Decrypted message: " + decrypted);
    }
    
    // Real AES encryption (returns Base64 string)
    private static String realEncrypt(String plaintext, SecretKeySpec secretKey, IvParameterSpec ivSpec) 
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    // Creates fixed-length display version
    private static String createFixedLengthDisplay(String fullCipher, int targetLength) {
        StringBuilder result = new StringBuilder();
        byte[] bytes = fullCipher.getBytes(StandardCharsets.UTF_8);
        
        for (int i = 0; i < targetLength && i < bytes.length; i++) {
            // Convert to A-Z characters
            char c = (char)('A' + (Math.abs(bytes[i]) % 26));
            result.append(c);
        }
        
        // Pad if needed
        while (result.length() < targetLength) {
            result.append('X'); // Padding character
        }
        
        return result.toString();
    }
    
    // Real AES decryption
    private static String realDecrypt(String fullCipher, SecretKeySpec secretKey, IvParameterSpec ivSpec) 
            throws Exception {
        byte[] encrypted = Base64.getDecoder().decode(fullCipher);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
    
    private static SecretKeySpec generateKeyFromShift(int shiftKey) {
        String baseKey = "SECRET" + shiftKey;
        byte[] keyBytes = new byte[32];
        System.arraycopy(baseKey.getBytes(StandardCharsets.UTF_8), 0, keyBytes, 0, 
            Math.min(baseKey.length(), keyBytes.length));
        return new SecretKeySpec(keyBytes, "AES");
    }
}