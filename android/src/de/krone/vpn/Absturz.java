package de.krone.vpn;

import android.content.Context;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Absturz-Protokolle: stuerzt die App ab (Java oder Rust-Kern), landet ein Textprotokoll in files/absturz/. Beim
 * naechsten Verbinden geht es verschluesselt durch den Tunnel an den eigenen Server (Ordner absturz-logs); erst wenn
 * der Server den Empfang bestaetigt, wird die Datei hier geloescht.
 */
final class Absturz {
    private Absturz() {}

    private static boolean installed;
    private static final Set<String> queued = new HashSet<>();

    static File dir(Context c) {
        return new File(c.getApplicationContext().getFilesDir(), "absturz");
    }

    /** einmal je Prozess: Java-Abstuerze abfangen, Rust-Kern bekommt den Ordner */
    static synchronized void install(Context ctx) {
        if (installed) return;
        installed = true;
        final Context c = ctx.getApplicationContext();
        File d = dir(c);
        //noinspection ResultOfMethodCallIgnored
        d.mkdirs();
        try {
            Native.crashDir(d.getAbsolutePath());
        } catch (Throwable ignored) {
        }
        final Thread.UncaughtExceptionHandler prev = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                String text = "KroneVPN Android " + Native.version() + " – Absturz (Java)\n"
                        + "Gerät: " + Build.MANUFACTURER + " " + Build.MODEL + " · Android " + Build.VERSION.RELEASE + " (API " + Build.VERSION.SDK_INT + ")\n"
                        + "Thread: " + t.getName() + "\n"
                        + "VPN: " + (KroneVpnService.handle != 0 ? "an" : "aus") + " · letzter Fehler: " + KroneVpnService.lastError + "\n\n"
                        + sw;
                if (text.length() > 40000) text = text.substring(0, 40000);
                try (FileOutputStream o = new FileOutputStream(new File(d, (System.currentTimeMillis() / 1000) + "-java.txt"))) {
                    o.write(text.getBytes(StandardCharsets.UTF_8));
                }
            } catch (Throwable ignored) {
            }
            if (prev != null) prev.uncaughtException(t, e);
        });
    }

    /** vorhandene Protokolle zum Senden vormerken (nach dem Verbinden und regelmaessig) */
    static void upload(Context c) {
        long h = KroneVpnService.handle;
        if (h == 0) return;
        File[] fs = dir(c).listFiles((x, n) -> n.endsWith(".txt"));
        if (fs == null) return;
        Arrays.sort(fs);
        for (File f : fs) {
            synchronized (queued) {
                if (!queued.add(f.getName() + "@" + h)) continue;
            }
            try {
                byte[] b = new byte[(int) Math.min(f.length(), 48 * 1024)];
                try (java.io.FileInputStream in = new java.io.FileInputStream(f)) {
                    int n = 0, r;
                    while (n < b.length && (r = in.read(b, n, b.length - n)) > 0) n += r;
                }
                Native.crash(h, f.getName(), new String(b, StandardCharsets.UTF_8));
            } catch (Exception ignored) {
            }
        }
    }

    /** vom Server bestaetigte Protokolle loeschen (Status-JSON "crash_ok") */
    static void confirmed(Context c, JSONObject status) {
        JSONArray ok = status.optJSONArray("crash_ok");
        if (ok == null) return;
        for (int i = 0; i < ok.length(); i++) {
            String n = ok.optString(i, "");
            if (n.isEmpty() || n.contains("/")) continue;
            //noinspection ResultOfMethodCallIgnored
            new File(dir(c), n).delete();
        }
    }
}
