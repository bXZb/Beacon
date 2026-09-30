/*
 * Dump teamserver public key from .cobaltstrike.beacon_keys
 * (same approach as CobaltStrike-Linux-Beacon/generate-payload/Dump.java)
 *
 * On teamserver host, next to .cobaltstrike.beacon_keys:
 *   java -cp /path/to/cobaltstrike.jar DumpPublicKey.java
 *   # or compile DumpPublicKey class and run with CS jar on classpath
 *
 * Writes publickey.txt (hex-encoded SubjectPublicKeyInfo DER).
 * Then on build host:
 *   python3 tools/hexkey_to_der.py publickey.txt tools/fixtures/publickey.der
 */
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import common.CommonUtils;

class DumpPublicKey {
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            File file = new File(".cobaltstrike.beacon_keys");
            if (!file.exists()) {
                System.out.println("Could not find .cobaltstrike.beacon_keys");
                return;
            }
            KeyPair keyPair = (KeyPair) CommonUtils.readObject(file, null);
            String publicKeyHex = bytesToHex(keyPair.getPublic().getEncoded());
            Files.write(Path.of("publickey.txt"), publicKeyHex.getBytes());
            System.out.println("Public key written to publickey.txt");
        } catch (Exception exception) {
            System.out.println("Could not read asymmetric keys: " + exception);
        }
    }
}
