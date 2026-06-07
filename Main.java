import java.util.*;
import java.util.Base64;
import java.util.regex.*;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;

// ============================================================
//  INTERFACES
// ============================================================
interface Manageable {
    void display();
    String getSummary();
}

interface Encryptable {
    String encrypt(String text, int key);
    String decrypt(String text, int key);
}

// ============================================================
//  INPUT VALIDATOR
// ============================================================
class InputValidator {
    public static boolean isValidEmail(String email) {
        if (email == null || email.isBlank()) return false;
        String regex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        return Pattern.matches(regex, email.trim());
    }
    public static boolean isValidUrl(String url) {
        if (url == null || url.isBlank()) return false;
        String regex = "^(https?://)[A-Za-z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+$";
        return Pattern.matches(regex, url.trim());
    }
    public static boolean isValidMasterPassword(String pwd) {
        return pwd != null && pwd.length() >= 6;
    }
    public static boolean isNonBlank(String s) {
        return s != null && !s.isBlank();
    }
    public static boolean isIntInRange(String s, int min, int max) {
        try { int v = Integer.parseInt(s.trim()); return v >= min && v <= max; }
        catch (NumberFormatException e) { return false; }
    }
    public static String emailError(String email) {
        if (email == null || email.isBlank())         return "    Email cannot be empty.";
        if (!email.contains("@"))                     return "    Email must contain '@' (e.g. user@gmail.com).";
        if (email.indexOf('@') == 0)                  return "    Missing username before '@'.";
        if (!email.contains("."))                     return "    Email must contain a domain with '.' (e.g. .com).";
        String[] parts = email.split("@");
        if (parts.length != 2 || parts[1].isBlank())  return "    Missing domain after '@'.";
        return "   Invalid email format. Use: user@example.com";
    }
    public static String urlError(String url) {
        if (url == null || url.isBlank())                                     return "    URL cannot be empty.";
        if (!url.startsWith("http://") && !url.startsWith("https://"))        return "    URL must start with 'http://' or 'https://'.";
        return "   Invalid URL format. Example: https://gmail.com";
    }
}

// ============================================================
//  FILE ENCRYPTION LAYER  (XOR + Base64 — makes JSON unreadable)
// ============================================================
class FileEncryption {

    /** Secret file-level key — change this to any passphrase you like */
    private static final String FILE_KEY = "P@ssW0rd_V@ult_S3cr3t_K3y_2025!";

    /** Derive a repeating XOR key-stream from the passphrase */
    private static byte[] keyBytes() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(FILE_KEY.getBytes("UTF-8"));
        } catch (Exception e) {
            return FILE_KEY.getBytes();
        }
    }

    /** XOR every byte of data against the cycling key */
    private static byte[] xorTransform(byte[] data) {
        byte[] key    = keyBytes();
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    /** Encrypt plaintext → opaque Base64 string */
    public static String encryptData(String plaintext) {
        try {
            byte[] xored = xorTransform(plaintext.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(xored);
        } catch (Exception e) {
            return plaintext; // fallback: store as-is
        }
    }

    /** Decrypt opaque Base64 string → plaintext */
    public static String decryptData(String ciphertext) {
        try {
            byte[] decoded = Base64.getDecoder().decode(ciphertext.trim());
            return new String(xorTransform(decoded), "UTF-8");
        } catch (Exception e) {
            return ciphertext; // fallback: treat as plaintext
        }
    }
}

// ============================================================
//  STORAGE MANAGER  (encrypted .vault file)
// ============================================================
class StorageManager {
    private static final String DATA_DIR   = "vault_data";
    private static final String VAULT_FILE = DATA_DIR + File.separator + "vault.dat";
    static { new File(DATA_DIR).mkdirs(); }

    public static void saveUsers(ArrayList<User> users) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("[");
            for (int i = 0; i < users.size(); i++) {
                sb.append(userToJson(users.get(i)));
                if (i < users.size() - 1) sb.append(",");
            }
            sb.append("]");

            String encrypted = FileEncryption.encryptData(sb.toString());
            try (PrintWriter pw = new PrintWriter(new FileWriter(VAULT_FILE))) {
                pw.print(encrypted);
            }
        } catch (IOException e) {
            System.out.println("   Warning: Could not save data. " + e.getMessage());
        }
    }

    public static ArrayList<User> loadUsers() {
        ArrayList<User> users = new ArrayList<>();
        File f = new File(VAULT_FILE);
        if (!f.exists()) return users;
        try {
            String raw = new String(Files.readAllBytes(f.toPath())).trim();
            if (raw.isEmpty()) return users;

            // Try decrypting (new format)
            String content = FileEncryption.decryptData(raw).trim();

            // If decryption produced something that isn't JSON, it might be a legacy plain file
            if (!content.startsWith("[")) content = raw.trim();
            if (content.isEmpty() || content.equals("[]")) return users;

            for (String block : splitJsonObjects(content)) {
                User u = parseUser(block);
                if (u != null) users.add(u);
            }
        } catch (IOException e) {
            System.out.println("   Warning: Could not load saved data. Starting fresh.");
        }
        return users;
    }

    // ── Serialisation helpers ────────────────────────────────
    private static String userToJson(User u) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"name\":\"").append(escape(u.getName())).append("\",");
        sb.append("\"email\":\"").append(escape(u.getEmail())).append("\",");
        sb.append("\"masterPassword\":\"").append(escape(u.getMasterPasswordHash())).append("\",");
        sb.append("\"vault\":[");
        ArrayList<VaultEntry> vault = u.getVault();
        for (int i = 0; i < vault.size(); i++) {
            sb.append(entryToJson(vault.get(i)));
            if (i < vault.size() - 1) sb.append(",");
        }
        sb.append("]}");
        return sb.toString();
    }

    private static String entryToJson(VaultEntry e) {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"type\":\"").append(e.getType()).append("\",");
        sb.append("\"title\":\"").append(escape(e.getTitle())).append("\",");
        sb.append("\"username\":\"").append(escape(e.getUsername())).append("\",");
        sb.append("\"createdAt\":\"").append(escape(e.getCreatedAt())).append("\",");
        if (e instanceof PasswordEntry) {
            PasswordEntry pe = (PasswordEntry) e;
            sb.append("\"encryptedPassword\":\"").append(escape(pe.getEncryptedPassword())).append("\",");
            sb.append("\"websiteUrl\":\"").append(escape(pe.getWebsiteUrl())).append("\"");
        } else if (e instanceof NoteEntry) {
            NoteEntry ne = (NoteEntry) e;
            sb.append("\"noteContent\":\"").append(escape(ne.getNoteContent())).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static User parseUser(String json) {
        try {
            String name   = extractJsonString(json, "name");
            String email  = extractJsonString(json, "email");
            String pwHash = extractJsonString(json, "masterPassword");
            if (name == null || email == null || pwHash == null) return null;
            User u = new User(name, email, pwHash, true);
            int vaultStart = json.indexOf("\"vault\":[");
            if (vaultStart != -1) {
                String vaultSection = json.substring(vaultStart + 9);
                for (String eb : splitJsonObjects(vaultSection)) {
                    VaultEntry ve = parseEntry(eb);
                    if (ve != null) u.getVault().add(ve);
                }
            }
            return u;
        } catch (Exception e) { return null; }
    }

    private static VaultEntry parseEntry(String json) {
        try {
            String type      = extractJsonString(json, "type");
            String title     = extractJsonString(json, "title");
            String username  = extractJsonString(json, "username");
            String createdAt = extractJsonString(json, "createdAt");
            if (type == null || title == null) return null;
            if ("PASSWORD".equals(type)) {
                String encPwd = extractJsonString(json, "encryptedPassword");
                String url    = extractJsonString(json, "websiteUrl");
                return PasswordEntry.fromStorage(title, username, encPwd, url, createdAt);
            } else if ("NOTE".equals(type)) {
                String content = extractJsonString(json, "noteContent");
                return NoteEntry.fromStorage(title, content, createdAt);
            }
        } catch (Exception ignored) {}
        return null;
    }

    private static String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int start = json.indexOf(pattern);
        if (start == -1) return null;
        start += pattern.length();
        int end = start;
        while (end < json.length()) {
            if (json.charAt(end) == '"' && json.charAt(end - 1) != '\\') break;
            end++;
        }
        return unescape(json.substring(start, end));
    }

    private static String[] splitJsonObjects(String json) {
        List<String> objects = new ArrayList<>();
        int depth = 0, start = -1;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') { if (depth++ == 0) start = i; }
            else if (c == '}') { if (--depth == 0 && start != -1) objects.add(json.substring(start, i + 1)); }
        }
        return objects.toArray(new String[0]);
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
    private static String unescape(String s) {
        if (s == null) return "";
        return s.replace("\\\"", "\"").replace("\\\\", "\\").replace("\\n", "\n").replace("\\r", "\r");
    }
}

// ============================================================
//  VAULT ENTRY (abstract base)
// ============================================================
abstract class VaultEntry implements Manageable {
    protected String title;
    protected String username;
    protected String createdAt;

    public VaultEntry(String title, String username) {
        this.title = title; this.username = username;
        this.createdAt = new java.util.Date().toString();
    }
    public VaultEntry(String title, String username, String createdAt) {
        this.title = title; this.username = username; this.createdAt = createdAt;
    }
    public String getTitle()     { return title; }
    public String getUsername()  { return username; }
    public String getCreatedAt() { return createdAt; }
    public void setTitle(String t)    { this.title    = t; }
    public void setUsername(String u) { this.username = u; }
    public abstract String getType();
    public abstract String getMaskedSecret();
}

// ============================================================
//  CIPHER ENGINE
// ============================================================
class CipherEngine implements Encryptable {
    private static final int SHIFT_KEY = 7;

    @Override
    public String encrypt(String text, int key) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                sb.append((char) ((c - base + key) % 26 + base));
            } else if (Character.isDigit(c)) {
                sb.append((char) ((c - '0' + key) % 10 + '0'));
            } else { sb.append(c); }
        }
        return Base64.getEncoder().encodeToString(sb.toString().getBytes());
    }

    @Override
    public String decrypt(String text, int key) {
        try {
            String decoded = new String(Base64.getDecoder().decode(text));
            StringBuilder sb = new StringBuilder();
            for (char c : decoded.toCharArray()) {
                if (Character.isLetter(c)) {
                    char base = Character.isUpperCase(c) ? 'A' : 'a';
                    sb.append((char) ((c - base - key + 26) % 26 + base));
                } else if (Character.isDigit(c)) {
                    sb.append((char) ((c - '0' - key + 10) % 10 + '0'));
                } else { sb.append(c); }
            }
            return sb.toString();
        } catch (Exception e) { return "[DECRYPT ERROR]"; }
    }

    public static int defaultKey() { return SHIFT_KEY; }
}

// ============================================================
//  PASSWORD STRENGTH CHECKER
// ============================================================
class PasswordStrengthChecker {
    public static String check(String password) {
        int score = 0;
        List<String> tips = new ArrayList<>();
        if (password.length() >= 8)  score++;
        else tips.add("  • At least 8 characters needed");
        if (password.length() >= 12) score++;
        else if (password.length() >= 8) tips.add("  • Use 12+ chars for extra strength");
        if (password.matches(".*[A-Z].*")) score++;
        else tips.add("  • Add uppercase letters (A-Z)");
        if (password.matches(".*[a-z].*")) score++;
        else tips.add("  • Add lowercase letters (a-z)");
        if (password.matches(".*\\d.*"))   score++;
        else tips.add("  • Add numbers (0-9)");
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) score++;
        else tips.add("  • Add special characters (!@#$%^&*)");
        String bar   = buildBar(score);
        String label = getLabel(score);
        StringBuilder result = new StringBuilder();
        result.append("\n");
        result.append("  ║   PASSWORD STRENGTH ANALYSIS          \n");
        result.append("  ╠---------------------------------------\n");
        result.append(String.format("  ║  Strength  : %-29s %n", label));
        result.append(String.format("  ║  Score     : %d / 6 %-24s %n", score, ""));
        result.append(String.format("  ║  Meter     : %-29s %n", bar));
        result.append("  ╠--------------------------------------------\n");
        if (tips.isEmpty()) {
            result.append("  ║   Perfect! No improvements needed.   \n");
        } else {
            result.append("  ║   Suggestions:                        \n");
            for (String t : tips) result.append(String.format("  ║  %-43s %n", t));
        }
        result.append("  ╚---------------------------------------------\n");
        return result.toString();
    }
    private static String buildBar(int score) { return "[" + "█".repeat(score) + "░".repeat(6 - score) + "]"; }
    private static String getLabel(int score) {
        if (score <= 1) return "🔴 VERY WEAK";
        if (score == 2) return "🟠 WEAK";
        if (score == 3) return "🟡 FAIR";
        if (score == 4) return "🟢 GOOD";
        if (score == 5) return "🔵 STRONG";
        return "⭐ EXCELLENT";
    }
}

// ============================================================
//  PASSWORD GENERATOR
// ============================================================
class PasswordGenerator {
    private static final String UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER   = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS  = "0123456789";
    private static final String SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";

    public static String generate(int length, boolean useUpper, boolean useLower,
                                  boolean useDigits, boolean useSymbols) {
        StringBuilder pool      = new StringBuilder();
        StringBuilder mandatory = new StringBuilder();
        Random rnd = new Random();
        if (useUpper)   { pool.append(UPPER);   mandatory.append(UPPER.charAt(rnd.nextInt(UPPER.length()))); }
        if (useLower)   { pool.append(LOWER);   mandatory.append(LOWER.charAt(rnd.nextInt(LOWER.length()))); }
        if (useDigits)  { pool.append(DIGITS);  mandatory.append(DIGITS.charAt(rnd.nextInt(DIGITS.length()))); }
        if (useSymbols) { pool.append(SYMBOLS); mandatory.append(SYMBOLS.charAt(rnd.nextInt(SYMBOLS.length()))); }
        if (pool.length() == 0) pool.append(LOWER).append(DIGITS);
        StringBuilder pwd = new StringBuilder(mandatory);
        String p = pool.toString();
        for (int i = pwd.length(); i < length; i++) pwd.append(p.charAt(rnd.nextInt(p.length())));
        List<Character> chars = new ArrayList<>();
        for (char c : pwd.toString().toCharArray()) chars.add(c);
        Collections.shuffle(chars);
        StringBuilder result = new StringBuilder();
        for (char c : chars) result.append(c);
        return result.toString();
    }
}

// ============================================================
//  TEXT CASE CONVERTER
// ============================================================
class TextCaseConverter {
    public static String convert(String text, int mode) {
        switch (mode) {
            case 1: return text.toUpperCase();
            case 2: return text.toLowerCase();
            case 3: return toTitleCase(text);
            case 4: return toCamelCase(text);
            case 5: return toSnakeCase(text);
            case 6: return toKebabCase(text);
            case 7: return reverseText(text);
            default: return text;
        }
    }
    private static String toTitleCase(String text) {
        String[] words = text.toLowerCase().split("\\s+");
        StringBuilder sb = new StringBuilder();
        for (String w : words) if (!w.isEmpty()) sb.append(Character.toUpperCase(w.charAt(0))).append(w.substring(1)).append(" ");
        return sb.toString().trim();
    }
    private static String toCamelCase(String text) {
        String[] words = text.trim().split("[\\s_\\-]+");
        StringBuilder sb = new StringBuilder(words[0].toLowerCase());
        for (int i = 1; i < words.length; i++)
            if (!words[i].isEmpty()) sb.append(Character.toUpperCase(words[i].charAt(0))).append(words[i].substring(1).toLowerCase());
        return sb.toString();
    }
    private static String toSnakeCase(String text) { return text.trim().replaceAll("[\\s\\-]+", "_").toLowerCase(); }
    private static String toKebabCase(String text)  { return text.trim().replaceAll("[\\s_]+", "-").toLowerCase(); }
    private static String reverseText(String text)  { return new StringBuilder(text).reverse().toString(); }
}

// ============================================================
//  VAULT STATS REPORT
// ============================================================
class VaultStatsReport {
    public static void print(ArrayList<VaultEntry> vault) {
        int passwords = 0, notes = 0, weakCount = 0, fairCount = 0, goodCount = 0, strongCount = 0;
        List<String> weakTitles = new ArrayList<>();
        for (VaultEntry e : vault) {
            if (e instanceof PasswordEntry) {
                passwords++;
                PasswordEntry pe = (PasswordEntry) e;
                int score = scorePassword(pe.getDecryptedPassword());
                if (score <= 2) { weakCount++; weakTitles.add(pe.getTitle()); }
                else if (score == 3) fairCount++;
                else if (score == 4) goodCount++;
                else strongCount++;
            } else { notes++; }
        }
        int total = passwords + notes;
        System.out.println("\n");
        System.out.println("  ║    VAULT STATISTICS REPORT        ");
        System.out.println("  ╠-----------------------------------");
        System.out.printf ("  ║  Total Entries    : %-23d %n", total);
        System.out.printf ("  ║  Passwords        : %-23d %n", passwords);
        System.out.printf ("  ║  Secure Notes     : %-23d %n", notes);
        System.out.println("  ╠--------------------------------------------");
        System.out.println("\n");
        System.out.println("  ║   PASSWORD HEALTH BREAKDOWN       ");
        System.out.println("  ╠--------------------------------- \n");
        System.out.printf ("  ║  ⭐ Strong / Excellent : %-17d %n", strongCount);
        System.out.printf ("  ║  🟢 Good               : %-17d %n", goodCount);
        System.out.printf ("  ║  🟡 Fair               : %-17d %n", fairCount);
        System.out.printf ("  ║  🔴 Weak / Very Weak   : %-17d %n", weakCount);
        if (!weakTitles.isEmpty()) {
            System.out.println("\n");
        System.out.println("  ║             Weak Password Entries:          ");
            for (String t : weakTitles) System.out.printf("  ║    • %-37s %n", t);
        }
        System.out.println("  ╚--------------------------- -------\n");
    }
    private static int scorePassword(String password) {
        int score = 0;
        if (password.length() >= 8)  score++;
        if (password.length() >= 12) score++;
        if (password.matches(".*[A-Z].*")) score++;
        if (password.matches(".*[a-z].*")) score++;
        if (password.matches(".*\\d.*"))   score++;
        if (password.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>\\/?].*")) score++;
        return score;
    }
}

// ============================================================
//  PASSWORD LEAK CHECKER
// ============================================================
class PasswordLeakChecker {
    private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
            "password","123456","123456789","qwerty","abc123","111111","password1",
            "iloveyou","admin","welcome","monkey","dragon","master","letmein",
            "login","hello","sunshine","princess","football","shadow","superman",
            "michael","batman","trustno1","1234","12345","pass","test","guest","root"));

    public static void check(String password) {
        System.out.println("\n");
        System.out.println("  ║     LEAK / COMMON PASSWORD CHECK     ");
        System.out.println("  ╠---------------------------- ---------");
        boolean isCommon = COMMON_PASSWORDS.contains(password.toLowerCase());
        boolean allSame  = password.chars().distinct().count() == 1;
        boolean isSeq    = isSequential(password);
        if (isCommon) {
            System.out.println("  ║     DANGER: This is a very common         ");
            System.out.println("  ║     password — likely already leaked!     ");
        } else if (allSame) {
            System.out.println("  ║     DANGER: All characters are the same!  ");
            System.out.println("  ║     e.g. 'aaaaaaa' — extremely weak!      ");
        } else if (isSeq) {
            System.out.println("  ║     WARNING: Sequential pattern found!   ");
            System.out.println("  ║     e.g. '123456' or 'abcdef'             ");
        } else {
            System.out.println("  ║     Not found in common password list.    ");
            System.out.println("  ║     Still use a unique strong password!   ");
        }
            System.out.println("  ╚-----------------------------------------\n");
    }
    private static boolean isSequential(String password) {
        if (password.length() < 4) return false;
        boolean ascending = true, descending = true;
        for (int i = 0; i < password.length() - 1; i++) {
            if (password.charAt(i + 1) - password.charAt(i) != 1) ascending  = false;
            if (password.charAt(i) - password.charAt(i + 1) != 1) descending = false;
        }
        return ascending || descending;
    }
}

// ============================================================
//  PASSWORD ENTRY
// ============================================================
class PasswordEntry extends VaultEntry {
    private String encryptedPassword;
    private String websiteUrl;
    private static final CipherEngine cipher = new CipherEngine();

    public PasswordEntry(String title, String username, String rawPassword, String websiteUrl) {
        super(title, username);
        this.encryptedPassword = cipher.encrypt(rawPassword, CipherEngine.defaultKey());
        this.websiteUrl = websiteUrl;
    }
    public static PasswordEntry fromStorage(String title, String username,
                                            String encryptedPwd, String url, String createdAt) {
        PasswordEntry pe = new PasswordEntry(title, username, "", url);
        pe.encryptedPassword = encryptedPwd; pe.createdAt = createdAt; return pe;
    }
    public String getDecryptedPassword() { return cipher.decrypt(encryptedPassword, CipherEngine.defaultKey()); }
    public String getEncryptedPassword() { return encryptedPassword; }
    public String getWebsiteUrl()        { return websiteUrl; }

    @Override public String getType() { return "PASSWORD"; }

    @Override
    public String getMaskedSecret() {
        String raw = getDecryptedPassword();
        if (raw.length() <= 2) return "**";
        return raw.charAt(0) + "*".repeat(raw.length() - 2) + raw.charAt(raw.length() - 1);
    }

    @Override
    public void display() {
        System.out.println("\n");
        System.out.printf ("  ║  [PASSWORD]  %-26s║ %n", shorten(title, 26));
        System.out.println("  ╠--------------------------------------------");
        System.out.printf ("  ║  Username  : %-30s %n", shorten(username, 30));
        System.out.printf ("  ║  Password  : %-30s %n", shorten(getMaskedSecret(), 30));
        System.out.printf ("  ║  URL       : %-30s %n", shorten(websiteUrl, 30));
        System.out.printf ("  ║  Saved on  : %-30s %n", shorten(createdAt.length() >= 24 ? createdAt.substring(0,24) : createdAt, 30));
        System.out.println("  ╚--------------------------------------------");
    }

    @Override
    public String getSummary() {
        return String.format("🔑 [PASSWORD] %-18s | User: %-18s | %s", shorten(title,18), shorten(username,18), shorten(websiteUrl,28));
    }
    private String shorten(String s, int max) { return s.length() <= max ? s : s.substring(0, max - 2) + ".."; }
}

// ============================================================
//  NOTE ENTRY
// ============================================================
class NoteEntry extends VaultEntry {
    private String noteContent;

    public NoteEntry(String title, String noteContent) { super(title, "N/A"); this.noteContent = noteContent; }
    public static NoteEntry fromStorage(String title, String content, String createdAt) {
        NoteEntry ne = new NoteEntry(title, content); ne.createdAt = createdAt; return ne;
    }
    public String getNoteContent()          { return noteContent; }
    public void setNoteContent(String note) { this.noteContent = note; }

    @Override public String getType() { return "NOTE"; }

    @Override
    public String getMaskedSecret() {
        if (noteContent.length() <= 10) return "**hidden**";
        return noteContent.substring(0, 6) + "...";
    }

    @Override
    public void display() {
        System.out.println("\n");
        System.out.printf ("  ║   [SECURE NOTE]  %-23s║%n", shorten(title, 23));
        System.out.println("  ╠-----------------------------------------");
        System.out.printf ("  ║  Content  : %-30s %n", shorten(noteContent, 30));
        System.out.printf ("  ║  Saved on : %-30s %n", shorten(createdAt.length() >= 24 ? createdAt.substring(0,24) : createdAt, 30));
        System.out.println("  ╚------------------------------------------");
    }

    @Override
    public String getSummary() {
        return String.format("📝 [NOTE]     %-23s | Preview: %s", shorten(title, 23), getMaskedSecret());
    }
    private String shorten(String s, int max) { return s.length() <= max ? s : s.substring(0, max - 2) + ".."; }
}

// ============================================================
//  USER
// ============================================================
class User {
    private String name;
    private String email;
    private String masterPassword;
    private ArrayList<VaultEntry> vault = new ArrayList<>();

    public User(String name, String email, String masterPassword) {
        this.name = name; this.email = email; this.masterPassword = masterPassword;
    }
    public User(String name, String email, String masterPassword, boolean alreadyHashed) {
        this.name = name; this.email = email; this.masterPassword = masterPassword;
    }
    public String getName()               { return name; }
    public String getEmail()              { return email; }
    public String getMasterPasswordHash() { return masterPassword; }
    public boolean checkPassword(String pwd) { return masterPassword.equals(pwd); }
    public void changeMasterPassword(String newPwd) { this.masterPassword = newPwd; }
    public void clearVault()              { vault.clear(); }
    public ArrayList<VaultEntry> getVault() { return vault; }

    public void addEntry(VaultEntry entry) {
        vault.add(entry);
        System.out.println("  Entry saved (encrypted): " + entry.getTitle());
    }

    public boolean deleteEntry(int i) {
        if (i < 0 || i >= vault.size()) return false;
        System.out.println("  🗑️  Deleted: " + vault.get(i).getTitle());
        vault.remove(i); return true;
    }

    public void listVault() {
        if (vault.isEmpty()) { System.out.println("    Vault is empty."); return; }
        System.out.println();
        System.out.printf ("  ║     YOUR VAULT  —  %d %-42s║%n", vault.size(), vault.size() == 1 ? "entry" : "entries");
        System.out.println("  ╠---------------------------------------------------------------- ");
        for (int i = 0; i < vault.size(); i++)
            System.out.printf("  ║  [%2d]  %-56s║%n", i + 1, shorten(vault.get(i).getSummary(), 56));
        System.out.println("  ╚--------------------------------------\n");
    }

    public void viewEntry(int i) {
        if (i < 0 || i >= vault.size()) { System.out.println("   Invalid index."); return; }
        vault.get(i).display();
    }

    public void revealEntry(int i) {
        if (i < 0 || i >= vault.size()) { System.out.println("   Invalid index."); return; }
        VaultEntry e = vault.get(i);
        System.out.println("  ║     DECRYPTED ENTRY     ");
        System.out.println("  ╠-------------------------");
        if (e instanceof PasswordEntry) {
            PasswordEntry pe = (PasswordEntry) e;
            System.out.printf("  ║  Title    : %-30s %n", shorten(pe.getTitle(), 30));
            System.out.printf("  ║  Username : %-30s %n", shorten(pe.getUsername(), 30));
            System.out.printf("  ║  Password : %-30s %n", shorten(pe.getDecryptedPassword(), 30));
            System.out.printf("  ║  URL      : %-30s %n", shorten(pe.getWebsiteUrl(), 30));
        } else if (e instanceof NoteEntry) {
            NoteEntry ne = (NoteEntry) e;
            System.out.printf("  ║  Title   : %-31s %n", shorten(ne.getTitle(), 31));
            System.out.printf("  ║  Content : %-31s %n", shorten(ne.getNoteContent(), 31));
        }
        System.out.println("  ╚------------------------\n");
    }

    public void searchVault(String kw) {
        System.out.println("\n  🔍 Results for: \"" + kw + "\"");
        System.out.println("--─────────────────────────────");
        boolean found = false;
        for (int i = 0; i < vault.size(); i++) {
            VaultEntry e = vault.get(i);
            if (e.getTitle().toLowerCase().contains(kw.toLowerCase()) ||
                    e.getUsername().toLowerCase().contains(kw.toLowerCase())) {
                System.out.printf("  [%2d]  %s%n", i + 1, e.getSummary()); found = true;
            }
        }
        if (!found) System.out.println("  No matching entries found.");
        System.out.println();
    }

    private String shorten(String s, int max) { return s.length() <= max ? s : s.substring(0, max - 2) + ".."; }
}

// ============================================================
//  AUTH MANAGER
// ============================================================
class AuthManager {
    private ArrayList<User> users;

    public AuthManager() {
        this.users = StorageManager.loadUsers();
        if (users.isEmpty()) { seedDemoData(); StorageManager.saveUsers(users); }
        System.out.println("  Vault data loaded. (" + users.size() + " account(s) found)");
    }

    private void seedDemoData() {
        User zeeshan = new User("Zeeshan Ali", "zeeshan@gmail.com", "zeeshan7822");
        zeeshan.getVault().add(new PasswordEntry("Gmail",     "zeeshanplus7822@gmail.com", "7822@Pass99",   "https://gmail.com"));
        zeeshan.getVault().add(new PasswordEntry("Facebook",  "zeeshan_ali",               "FbSecret#2025", "https://facebook.com"));
        zeeshan.getVault().add(new PasswordEntry("GitHub",    "zeeshan-ultra",             "Git$Hub77!",    "https://github.com"));
        zeeshan.getVault().add(new PasswordEntry("Instagram", "orewa_zeeshan",             "player456",     "https://instagram.com"));
        zeeshan.getVault().add(new NoteEntry("Bank PIN",      "HBL ATM PIN: 7822 | MCB: 3391"));
        zeeshan.getVault().add(new NoteEntry("WiFi Password", "Home WiFi: ZeeshanNet | Pass: Zeeshan#Home1"));
        users.add(zeeshan);

        User hassan = new User("Muhammad Hassan", "hassan@gmail.com", "hassan123");
        hassan.getVault().add(new PasswordEntry("Instagram", "hassan_official", "Insta!2025",  "https://instagram.com"));
        hassan.getVault().add(new PasswordEntry("LinkedIn",  "hassan@demo.com", "Link3d!nPro", "https://linkedin.com"));
        hassan.getVault().add(new NoteEntry("Server Keys", "AWS Key: AKIA****XYZ | Secret: s3cr3t!Key"));
        users.add(hassan);
    }

    public void persist() { StorageManager.saveUsers(users); }

    public User signup(Scanner sc) {

        System.out.println("  ║     CREATE ACCOUNT     ");
        System.out.println("  ╚- ----------------------");
        String name;
        while (true) {
            System.out.print("  Full Name : "); name = sc.nextLine().trim();
            if (InputValidator.isNonBlank(name)) break;
            System.out.println("  Name cannot be empty.");
        }
        String email;
        while (true) {
            System.out.print("  Email : "); email = sc.nextLine().trim();
            if (!InputValidator.isValidEmail(email)) { System.out.println(InputValidator.emailError(email)); continue; }
            boolean taken = false;
            for (User u : users) { if (u.getEmail().equalsIgnoreCase(email)) { taken = true; break; } }
            if (taken) { System.out.println("  Email already registered.\n"); continue; }
            break;
        }
        String pwd;
        while (true) {
            System.out.print("  Master Password : "); pwd = sc.nextLine().trim();
            if (!InputValidator.isValidMasterPassword(pwd)) { System.out.println("  Password too short — minimum 6 characters required."); continue; }
            System.out.print("  Confirm Password : "); String pwd2 = sc.nextLine().trim();
            if (!pwd.equals(pwd2)) { System.out.println("  Passwords don't match. Try again."); continue; }
            break;
        }
        System.out.println(PasswordStrengthChecker.check(pwd));
        User u = new User(name, email, pwd);
        users.add(u); persist();
        System.out.println("  Account created! Welcome, " + name + "!\n");
        return u;
    }

    public User login(Scanner sc) {

        System.out.println("  ║        LOG IN        ");
        System.out.println("  ╚----------------------");
        String email;
        while (true) {
            System.out.print("  Email : "); email = sc.nextLine().trim();
            if (InputValidator.isValidEmail(email)) break;
            System.out.println(InputValidator.emailError(email));
        }
        System.out.print("  Master Password : "); String pwd = sc.nextLine().trim();
        for (User u : users) {
            if (u.getEmail().equalsIgnoreCase(email) && u.checkPassword(pwd)) {
                System.out.println("  Welcome back, " + u.getName() + "!\n"); return u;
            }
        }
        System.out.println("  Invalid credentials. Check email and password.\n"); return null;
    }

    public boolean deleteAccount(User u) {
        boolean removed = users.remove(u);
        if (removed) persist(); return removed;
    }

    public ArrayList<User> getUsers() { return users; }
}

// ============================================================
//  MAIN CLASS
// ============================================================

public class Main {

    static Scanner    sc     = new Scanner(System.in);
    static CipherEngine cipher = new CipherEngine();
    static AuthManager auth;

    public static void main(String[] args) {
        printWelcome();
        auth = new AuthManager();

        User currentUser = null;
        while (currentUser == null) {
            printAuthMenu();
            String ch = sc.nextLine().trim();
            switch (ch) {
                case "1": currentUser = auth.signup(sc); break;
                case "2": currentUser = auth.login(sc);  break;
                case "3": bye(); break;
                default:  System.out.println("  Invalid choice. Enter 1, 2 or 3.\n");
            }
        }

        // ── MAIN LANDING MENU ────────────────────────────────
        boolean appRunning = true;
        while (appRunning) {
            printLandingMenu(currentUser);
            String choice = sc.nextLine().trim();
            switch (choice) {
                case "1":
                    // Dashboard loop
                    boolean dashRunning = true;
                    while (dashRunning) {
                        printDashboardMenu(currentUser);
                        String opt = sc.nextLine().trim();
                        switch (opt) {
                            case "1":  addPassword(currentUser);                break;
                            case "2":  addNote(currentUser);                    break;
                            case "3":  viewEntryPrompt(currentUser);            break;
                            case "4":  revealEntryPrompt(currentUser);          break;
                            case "5":  deleteEntryPrompt(currentUser);          break;
                            case "6":  searchPrompt(currentUser);               break;
                            case "7":  changeMasterPasswordTool(currentUser);   break;  // ← moved here
                            case "8":  clearVaultPrompt(currentUser);           break;
                            case "9":
                                deleteAccountPrompt(currentUser);
                                currentUser = reAuth();
                                if (currentUser == null) { appRunning = false; }
                                dashRunning = false;
                                break;
                            case "10": dashRunning = false; break;  // back to landing
                            default:   System.out.println("  Invalid option. Choose 1–10.\n");
                        }
                    }
                    break;

                case "2":
                    // Tools loop
                    boolean toolRunning = true;
                    while (toolRunning) {
                        printToolsMenu();
                        String opt = sc.nextLine().trim();
                        switch (opt) {
                            case "1":  encryptDecryptTool();     break;
                            case "2":  checkStrengthTool();      break;
                            case "3":  generatePasswordTool();   break;
                            case "4":  caseConverterTool();      break;
                            case "5":  vaultStatsTool(currentUser); break;
                            case "6":  leakCheckerTool();        break;
                            case "7":  toolRunning = false;      break;  // back
                            default:   System.out.println("  Invalid option. Choose 1–7.\n");
                        }
                    }
                    break;

                case "3":
                    System.out.println("  Logged out.\n");
                    currentUser = reAuth();
                    if (currentUser == null) appRunning = false;
                    break;

                case "4":
                    System.out.println("\n  Stay safe! Goodbye. \n");
                    appRunning = false;
                    break;

                default:
                    System.out.println("  Invalid choice. Enter 1, 2, 3 or 4.\n");
            }
        }
        sc.close();
    }

    // ── Re-authenticate helper ────────────────────────────────
    static User reAuth() {
        User u = null;
        while (u == null) {
            printAuthMenu();
            String c = sc.nextLine().trim();
            if      (c.equals("1")) u = auth.signup(sc);
            else if (c.equals("2")) u = auth.login(sc);
            else if (c.equals("3")) { bye(); return null; }
            else System.out.println("  Invalid choice.\n");
        }
        return u;
    }

    // ══════════════════════════════════════════════════════════
    //  VAULT / DASHBOARD ACTIONS
    // ══════════════════════════════════════════════════════════
    static void addPassword(User user) {

        System.out.println("  ║    ADD PASSWORD ENTRY      ");
        System.out.println("  ╚----------------------------");
        String title;
        while (true) {
            System.out.print("  Platform (e.g. Gmail) : "); title = sc.nextLine().trim();
            if (InputValidator.isNonBlank(title)) break;
            System.out.println("  Title cannot be empty.");
        }
        String uname;
        while (true) {
            System.out.print("  Username / Email : "); uname = sc.nextLine().trim();
            if (InputValidator.isNonBlank(uname)) break;
            System.out.println("  Username/Email cannot be empty.");
        }
        String pwd;
        while (true) {
            System.out.print("  Password            : "); pwd = sc.nextLine().trim();
            if (InputValidator.isNonBlank(pwd)) break;
            System.out.println("  Password cannot be empty.");
        }
        System.out.println(PasswordStrengthChecker.check(pwd));
        PasswordLeakChecker.check(pwd);
        String url;
        while (true) {
            System.out.print("  Website URL : "); url = sc.nextLine().trim();
            if (InputValidator.isValidUrl(url)) break;
            System.out.println(InputValidator.urlError(url));
        }
        user.addEntry(new PasswordEntry(title, uname, pwd, url));
        auth.persist();
    }

    static void addNote(User user) {

        System.out.println("  ║    ADD SECURE NOTE     ");
        System.out.println("  ╚------------------------");
        String title;
        while (true) {
            System.out.print("  Note Title : "); title = sc.nextLine().trim();
            if (InputValidator.isNonBlank(title)) break;
            System.out.println("  Title cannot be empty.");
        }
        String content;
        while (true) {
            System.out.print("  Note Content : "); content = sc.nextLine().trim();
            if (InputValidator.isNonBlank(content)) break;
            System.out.println("  Note content cannot be empty.");
        }
        user.addEntry(new NoteEntry(title, content));
        auth.persist();
    }

    static void viewEntryPrompt(User user) {
        user.listVault();
        if (user.getVault().isEmpty()) return;
        System.out.print("  Entry number: "); String input = sc.nextLine().trim();
        if (!InputValidator.isIntInRange(input, 1, user.getVault().size())) {
            System.out.println("  Enter a number between 1 and " + user.getVault().size() + "."); return;
        }
        user.viewEntry(Integer.parseInt(input) - 1);
    }

    static void revealEntryPrompt(User user) {
        user.listVault();
        if (user.getVault().isEmpty()) return;
        System.out.print("  Entry number to reveal: "); String input = sc.nextLine().trim();
        if (!InputValidator.isIntInRange(input, 1, user.getVault().size())) {
            System.out.println("  Enter a number between 1 and " + user.getVault().size() + "."); return;
        }
        System.out.print("  Confirm Master Password: ");
        if (user.checkPassword(sc.nextLine().trim())) {
            user.revealEntry(Integer.parseInt(input) - 1);
        } else {
            System.out.println("  Wrong master password!\n");
        }
    }

    static void deleteEntryPrompt(User user) {
        user.listVault();
        if (user.getVault().isEmpty()) return;
        System.out.print("  Entry number to delete: "); String input = sc.nextLine().trim();
        if (!InputValidator.isIntInRange(input, 1, user.getVault().size())) {
            System.out.println("  Enter a number between 1 and " + user.getVault().size() + "."); return;
        }
        if (!user.deleteEntry(Integer.parseInt(input) - 1)) System.out.println("  Could not delete entry.");
        auth.persist();
    }

    static void searchPrompt(User user) {
        System.out.print("  Search keyword: "); String kw = sc.nextLine().trim();
        if (!InputValidator.isNonBlank(kw)) { System.out.println("  Search keyword cannot be empty."); return; }
        user.searchVault(kw);
    }

    static void clearVaultPrompt(User user) {
        if (user.getVault().isEmpty()) { System.out.println("  Vault is already empty."); return; }

        System.out.println("  ║           CLEAR ENTIRE VAULT           ");
        System.out.printf ("  ║  This will DELETE all %-4d entries!    %n", user.getVault().size());
        System.out.println("  ╚----------------------------------------");
        System.out.print("  Confirm Master Password : ");
        if (!user.checkPassword(sc.nextLine().trim())) { System.out.println("  Wrong password. Aborted."); return; }
        System.out.print("  Type  YES  to confirm : ");
        if (!sc.nextLine().trim().equals("YES")) { System.out.println("  Cancelled."); return; }
        user.clearVault(); auth.persist();
        System.out.println("  Vault cleared successfully.\n");
    }

    static void deleteAccountPrompt(User user) {

        System.out.println("  ║              DELETE ACCOUNT                ");
        System.out.println("  ║   Your account + all vault data will be    ");
        System.out.println("  ║   permanently erased. Cannot be undone!    ");
        System.out.println("  ╚--------------------------------------------");
        System.out.print("  Confirm Master Password : ");
        if (!user.checkPassword(sc.nextLine().trim())) { System.out.println("  Wrong password. Aborted."); return; }
        System.out.print("  Type  DELETE  to confirm: ");
        if (!sc.nextLine().trim().equals("DELETE")) { System.out.println("  Cancelled."); return; }
        auth.deleteAccount(user);
        System.out.println("  Account deleted. Redirecting to login...\n");
    }

    // ══════════════════════════════════════════════════════════
    //  TOOLS
    // ══════════════════════════════════════════════════════════
    static void encryptDecryptTool() {
        System.out.println("\n");
        System.out.println("  ║             Ceaser Cipher TooL             ");
        System.out.println("  ╠--------------------------------------------");
        System.out.println("  ║    Algorithm : Caesar Cipher  +  Base64    ");
        System.out.println("  ║    Key Range : 1  to  26  (you choose!)    ");
        System.out.println("  ╠--------------------------------------------");
        System.out.println("  ║  1. Encrypt text                           ");
        System.out.println("  ║  2. Decrypt text                           ");
        System.out.println("  ╚--------------------------------------------");
        System.out.print("\n  Choose (1/2): "); String ch = sc.nextLine().trim();
        if (!ch.equals("1") && !ch.equals("2")) { System.out.println("  ❌ Invalid choice. Enter 1 or 2.\n"); return; }
        int userKey = 0;
        while (userKey < 1 || userKey > 26) {
            System.out.print("  Enter your Secret Key (1-26): "); String keyInput = sc.nextLine().trim();
            if (!InputValidator.isIntInRange(keyInput, 1, 26)) { System.out.println("  ❌ Key must be a number between 1 and 26."); continue; }
            userKey = Integer.parseInt(keyInput);
        }
        System.out.print("  Enter text: "); String text = sc.nextLine().trim();
        if (!InputValidator.isNonBlank(text)) { System.out.println("  ❌ Text cannot be empty.\n"); return; }
        if (ch.equals("1")) {
            String afterCaesar = applyCaesarOnly(text, userKey, false);
            String finalEnc    = Base64.getEncoder().encodeToString(afterCaesar.getBytes());

            System.out.println("  ║             ENCRYPTION STEPS               ");
            System.out.println("  ╠--------------------------------------------");
            System.out.printf ("  ║  Key Used     : %-27d %n", userKey);
            System.out.printf ("  ║  Original     : %-27s %n", shorten(text, 27));
            System.out.printf ("  ║  Step 1 Caesar: %-27s %n", shorten(afterCaesar, 27));
            System.out.printf ("  ║  Step 2 Base64: %-27s %n", shorten(finalEnc, 27));
            System.out.println("  ╠---------------------------------------------\n");
            System.out.println("  ║  FINAL ENCRYPTED OUTPUT:" +finalEnc );
            System.out.println("  ╚--------------------------------------------");
            System.out.println("\n  Save your key (" + userKey + ") to decrypt later!\n");
        } else {
            try {
                String decoded   = new String(Base64.getDecoder().decode(text));
                String decrypted = applyCaesarOnly(decoded, userKey, true);
                System.out.println("  ║              DECRYPTION STEPS              ");
                System.out.println("  ╠--------------------------------------------\n");
                System.out.printf ("  ║  Key Used      : %-26d %n", userKey);
                System.out.printf ("  ║  Encrypted     : %-26s %n", shorten(text, 26));
                System.out.printf ("  ║  Step 1 Base64 : %-26s %n", shorten(decoded, 26));
                System.out.printf ("  ║  Step 2 Caesar : %-26s %n", shorten(decrypted, 26));
                System.out.println("  ╠--------------------------------------------\n");
                System.out.println("  ║  FINAL DECRYPTED OUTPUT: "+ decrypted );
                System.out.println("  ╚---------------------------------------------");
            } catch (Exception e) { System.out.println("  Decryption failed! Wrong key or invalid Base64 text.\n"); }
        }
    }

    static void checkStrengthTool() {

        System.out.println("  ║   CHECK PASSWORD STRENGTH   ");
        System.out.println("  ╚---------------------------- ");
        String pwd;
        while (true) {
            System.out.print("  Enter password to check: "); pwd = sc.nextLine().trim();
            if (InputValidator.isNonBlank(pwd)) break;
            System.out.println("  Password cannot be empty.");
        }
        System.out.println(PasswordStrengthChecker.check(pwd));
        PasswordLeakChecker.check(pwd);
    }

    static void generatePasswordTool() {

        System.out.println("  ║   PASSWORD  GENERATOR   ");
        System.out.println("  ╚-------------------------");
        System.out.print("  Length (8-64, default 16): "); String lenStr = sc.nextLine().trim();
        int len = 16;
        if (InputValidator.isIntInRange(lenStr, 8, 64)) len = Integer.parseInt(lenStr);
        else if (!lenStr.isEmpty()) System.out.println("  Invalid length, using default (16).");
        System.out.print("  Include UPPERCASE? (y/n): "); boolean upper   = sc.nextLine().trim().equalsIgnoreCase("y");
        System.out.print("  Include lowercase? (y/n): "); boolean lower   = sc.nextLine().trim().equalsIgnoreCase("y");
        System.out.print("  Include digits?    (y/n): "); boolean digits  = sc.nextLine().trim().equalsIgnoreCase("y");
        System.out.print("  Include symbols?   (y/n): "); boolean symbols = sc.nextLine().trim().equalsIgnoreCase("y");
        System.out.println("\n");
        System.out.println("  ║   Generated Passwords  (pick one):   ");
        System.out.println("  ╠--------------------------------------");
        for (int i = 1; i <= 3; i++) {
            String p = PasswordGenerator.generate(len, upper, lower, digits, symbols);
            System.out.printf("  ║  [%d]  %-38s %n", i, p);
        }
        System.out.println("  ╚--------------------------------------");
        System.out.print("\n  Paste a password here to check its strength (or Enter to skip): ");
        String chosen = sc.nextLine().trim();
        if (!chosen.isEmpty()) { System.out.println(PasswordStrengthChecker.check(chosen)); PasswordLeakChecker.check(chosen); }
        System.out.println();
    }

    static void caseConverterTool() {
        System.out.println("\n");
        System.out.println("  ║    TEXT CASE CONVERTER    ");
        System.out.println("  ╠-------------------------\n");
        System.out.println("  ║  1. UPPERCASE             ");
        System.out.println("  ║  2. lowercase             ");
        System.out.println("  ║  3. Title Case            ");
        System.out.println("  ║  4. camelCase             ");
        System.out.println("  ║  5. snake_case            ");
        System.out.println("  ║  6. kebab-case            ");
        System.out.println("  ║  7. Reverse Text          ");
        System.out.println("  ╚---------------------------");
        int mode = 0;
        while (mode < 1 || mode > 7) {
            System.out.print("  Choose mode (1-7): "); String mInput = sc.nextLine().trim();
            if (InputValidator.isIntInRange(mInput, 1, 7)) { mode = Integer.parseInt(mInput); break; }
            System.out.println("  Enter a number between 1 and 7.");
        }
        System.out.print("  Enter text: "); String text = sc.nextLine().trim();
        if (!InputValidator.isNonBlank(text)) { System.out.println("  ❌ Text cannot be empty."); return; }
        String result = TextCaseConverter.convert(text, mode);
        System.out.println("\n");
        System.out.printf ("  ║  Input  : %-33s %n", shorten(text, 33));
        System.out.printf ("  ║  Output : %-33s %n", shorten(result, 33));
        System.out.println("  ╚---------------------------------------------");
        System.out.println("  Full output: " + result + "\n");
    }

    static void vaultStatsTool(User user) {
        if (user.getVault().isEmpty()) { System.out.println("  Vault is empty — nothing to report."); return; }
        VaultStatsReport.print(user.getVault());
    }

    static void leakCheckerTool() {
        System.out.println("\n");
        System.out.println("  ║   LEAK / COMMON PASSWORD CHECK   ");
        System.out.println("  ╚----------------------------------");
        String pwd;
        while (true) {
            System.out.print("  Enter password to check: "); pwd = sc.nextLine().trim();
            if (InputValidator.isNonBlank(pwd)) break;
            System.out.println("  Password cannot be empty.");
        }
        System.out.println(PasswordStrengthChecker.check(pwd));
        PasswordLeakChecker.check(pwd);
    }

    // ── Change Master Password (now in Dashboard) ────────────
    static void changeMasterPasswordTool(User user) {
        System.out.println("\n");
        System.out.println("  ║  CHANGE MASTER PASSWORD   ");
        System.out.println("  ╚---------------------------");
        System.out.print("  Current Master Password : "); String current = sc.nextLine().trim();
        if (!user.checkPassword(current)) { System.out.println("  Wrong current password. Aborted.\n"); return; }
        String newPwd;
        while (true) {
            System.out.print("  New Master Password : "); newPwd = sc.nextLine().trim();
            if (!InputValidator.isValidMasterPassword(newPwd)) { System.out.println("  Password too short — minimum 6 characters."); continue; }
            if (newPwd.equals(current)) { System.out.println("  New password must be different from current."); continue; }
            System.out.print("  Confirm New Password     : "); String confirm = sc.nextLine().trim();
            if (!newPwd.equals(confirm)) { System.out.println(" Passwords don't match. Try again."); continue; }
            break;
        }
        System.out.println(PasswordStrengthChecker.check(newPwd));
        user.changeMasterPassword(newPwd); auth.persist();
        System.out.println("  Master password updated successfully!\n");
    }

    // ══════════════════════════════════════════════════════════
    //  MENUS
    // ══════════════════════════════════════════════════════════
    static void printAuthMenu() {
        System.out.println("\n");
        System.out.println("  ║   PERSONAL PASSWORD MANAGER   ");
        System.out.println("  ╠-------------------------------");
        System.out.println("  ║   1.  Sign Up         ");
        System.out.println("  ║   2.  Log In          ");
        System.out.println("  ║   3.  Exit            ");
        System.out.println("  ╚------------------------- -----");
        System.out.print("\n  Choose: ");
    }

    static void printLandingMenu(User user) {
        System.out.println();
        System.out.println("\n");
        System.out.printf ("  ║  👤  %-37s║%n", shorten(user.getName() + "  |  " + user.getEmail(), 37));
        System.out.println("  ╠-----------------------------");
        System.out.println("  ║   1.  User Dashboard  (Vault)    ");
        System.out.println("  ║   2.  Tools          ");
        System.out.println("  ║   3.  Logout         ");
        System.out.println("  ║   4.  Exit           ");
        System.out.println("  ╚-----------------------------");
        System.out.print("\n  Choose: ");
    }

    static void printDashboardMenu(User user) {
        int count = user.getVault().size();
        System.out.println();
        System.out.printf ("  ║   DASHBOARD  —  %d %-23s║%n", count, count == 1 ? "entry" : "entries");
        System.out.println("  ╠--------------------------------------- ");
        System.out.println("  ║  ── Add ───────────────────────────────");
        System.out.println("  ║   1.  Add Password Entry               ");
        System.out.println("  ║   2.  Add Secure Note                  ");
        System.out.println("  ║  ── View ──────────────────────────────");
        System.out.println("  ║   3.  View Entry (masked)              ");
        System.out.println("  ║   4.  Reveal Entry (decrypt + auth)    ");
        System.out.println("  ║  ── Manage ────────────────────────────");
        System.out.println("  ║   5.  Delete Entry                     ");
        System.out.println("  ║   6.  Search Vault                     ");
        System.out.println("  ║   7.  Change Master Password           ");  // ← new lakin isy fiulhal use na krna logic nhi lga hai
        System.out.println("  ║   8.  Clear Entire Vault               ");
        System.out.println("  ║   9.  Delete My Account                ");
        System.out.println("  ║  10.  Back to Main Menu                ");
        System.out.println("  ╚--------------------------------------- ");
        System.out.print("\n  Choose: ");
    }

    static void printToolsMenu() {
        System.out.println();
        System.out.println("  ║               TOOLS                   ");
        System.out.println("  ╠---------------------------------------");
        System.out.println("  ║   1.  Encrypt / Decrypt Text          ");
        System.out.println("  ║   2.  Check Password Strength         ");
        System.out.println("  ║   3.  Generate Strong Password        ");
        System.out.println("  ║   4.  Text Case Converter             ");
        System.out.println("  ║   5.  Vault Stats Report              ");
        System.out.println("  ║   6.  Leak / Common Password Check    ");
        System.out.println("  ║   7.  Back to Main Menu               ");
        System.out.println("  ╚---------------------------------------");
        System.out.print("\n  Choose: ");
    }

    // ── Welcome Banner ────────────────────────────────────────
    static void printWelcome() {
        System.out.println();
        System.out.println("  ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗ ██████╗ ");
        System.out.println("  ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗██╔══██╗");
        System.out.println("  ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝██║  ██║");
        System.out.println("  ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗██║  ██║");
        System.out.println("  ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║██████╔╝");
        System.out.println("  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═════╝");
        System.out.println();
        System.out.println("  ███╗   ███╗ █████╗ ███╗  ██╗ █████╗  ██████╗ ███████╗██████╗ ");
        System.out.println("  ████╗ ████║██╔══██╗████╗ ██║██╔══██╗██╔════╝ ██╔════╝██╔══██╗");
        System.out.println("  ██╔████╔██║███████║██╔██╗██║███████║██║  ███╗█████╗  ██████╔╝");
        System.out.println("  ██║╚██╔╝██║██╔══██║██║╚████║██╔══██║██║   ██║██╔══╝  ██╔══██╗");
        System.out.println("  ██║ ╚═╝ ██║██║  ██║██║ ╚███║██║  ██║╚██████╔╝███████╗██║  ██║");
        System.out.println("  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝");
        System.out.println();
        System.out.println("  ╔----------------------------=-----------------------------------╗");
        System.out.println("  ║                by Zeeshan Ali and Muhammad Hassan              ║");
        System.out.println("  ║          Encrypt • Decrypt • Generate • Analyse • Store        ║");
        System.out.println("  ╚----------------------------------------------------------------╝");
        System.out.println();
    }

    // ══════════════════════════════════════════════════════════
    //  HELPERS
    // ══════════════════════════════════════════════════════════
    static String applyCaesarOnly(String text, int key, boolean reverse) {
        StringBuilder sb = new StringBuilder();
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                char base  = Character.isUpperCase(c) ? 'A' : 'a';
                int  shift = reverse ? (26 - key) : key;
                sb.append((char) ((c - base + shift) % 26 + base));
            } else if (Character.isDigit(c)) {
                int shift = reverse ? (10 - key % 10) : (key % 10);
                sb.append((char) ((c - '0' + shift) % 10 + '0'));
            } else { sb.append(c); }
        }
        return sb.toString();
    }

    static String shorten(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max - 2) + "..";
    }

    static void bye() {
        System.out.println("\n");
        System.out.println("████████╗██╗  ██╗ █████╗ ███╗   ██╗██╗  ██╗    ██╗   ██╗ ██████╗ ██╗   ██╗");
        System.out.println("╚══██╔══╝██║  ██║██╔══██╗████╗  ██║██║ ██╔╝    ╚██╗ ██╔╝██╔═══██╗██║   ██║");
        System.out.println("   ██║   ███████║███████║██╔██╗ ██║█████╔╝      ╚████╔╝ ██║   ██║██║   ██║");
        System.out.println("   ██║   ██╔══██║██╔══██║██║╚██╗██║██╔═██╗       ╚██╔╝  ██║   ██║██║   ██║");
        System.out.println("   ██║   ██║  ██║██║  ██║██║ ╚████║██║  ██╗       ██║   ╚██████╔╝╚██████╔╝");
        System.out.println("   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ");
        System.out.println("  ╔----------------------------=-----------------------------------╗");
        System.out.println("  ║             For usning the Personal Password Manager           ║");
        System.out.println("  ╚----------------------------------------------------------------╝");
        System.exit(0);
    }
}