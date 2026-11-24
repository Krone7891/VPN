package de.krone.vpn;

/** Ruft die Android-JNI-Bibliothek (Host-Build) genau wie KroneVpnService auf: parse -> start(fd) -> status -> stop. */
public class JniTest {
    public static void main(String[] a) throws Exception {
        int fd = Integer.parseInt(a[0]);
        String code = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(a[1]))).trim();
        int secs = Integer.parseInt(a[2]);
        // optional: Ordner fuer Updates (wie cacheDir/update in der App) -> warten, bis ein Update geladen ist
        String upd = a.length > 3 ? a[3] : "";
        System.out.println("version=" + Native.version());
        System.out.println("parse=" + Native.parse(code));
        System.out.println("parse(falsch)=" + Native.parse("hallo"));
        long h = Native.start(fd, code, "", upd);
        System.out.println("handle=" + (h != 0));
        String st = "";
        for (int i = 0; i < 100 && !st.contains("\"connected\""); i++) { Thread.sleep(100); st = Native.status(h); }
        System.out.println("status=" + st);
        Native.reconnect(h);
        Thread.sleep(1500);
        for (int i = 0; i < 100 && !Native.status(h).contains("\"connected\""); i++) Thread.sleep(100);
        System.out.println("nach reconnect=" + Native.status(h));
        System.out.println("READY");
        if (!upd.isEmpty()) {
            String s = Native.status(h);
            for (int i = 0; i < 600 && !s.matches(".*\"update_file\":\"[^\"]+\".*"); i++) { Thread.sleep(100); s = Native.status(h); }
            System.out.println("UPDATE=" + s);
        }
        Thread.sleep(secs * 1000L);
        System.out.println("vor stop=" + Native.status(h));
        Native.stop(h);
        System.out.println("STOPPED");
    }
}
