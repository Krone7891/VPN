package de.krone.vpn;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.net.VpnService;
import android.os.Build;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Automatische Aktualisierung: Der Rust-Kern laedt die neue APK ueber die VPN-Verbindung, prueft Signatur und
 * Pruefsumme und legt sie ab. Hier wird sie mit dem Paket-Installer von Android eingespielt.
 * Android prueft zusaetzlich, dass die neue APK mit demselben Schluessel signiert ist wie die installierte.
 * Ab Android 12 geht das ohne Rueckfrage (die App aktualisiert sich selbst); sonst fragt Android einmal nach.
 */
final class Updater {
    private Updater() {}

    /** Version, die gerade installiert wird */
    static volatile String installing = "";
    /** Version, deren Installation abgebrochen wurde/fehlschlug (nicht immer wieder versuchen) */
    static volatile String failed = "";
    /** wartet auf Bestaetigung durch den Nutzer */
    static volatile Intent confirm;
    static volatile String message = "";

    static void install(Context ctx, String path, String version, boolean byUser) {
        if (version.isEmpty() || version.equals(installing) || (!byUser && version.equals(failed))) return;
        File apk = new File(path);
        if (!apk.isFile()) return;
        installing = version;
        failed = "";
        message = "Update " + version + " wird installiert …";
        final Context app = ctx.getApplicationContext();
        new Thread(() -> {
            try {
                PackageInstaller pi = app.getPackageManager().getPackageInstaller();
                PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
                p.setAppPackageName(app.getPackageName());
                p.setSize(apk.length());
                if (Build.VERSION.SDK_INT >= 31) p.setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED);
                int id = pi.createSession(p);
                try (PackageInstaller.Session s = pi.openSession(id)) {
                    try (InputStream in = new FileInputStream(apk); OutputStream out = s.openWrite("update.apk", 0, apk.length())) {
                        byte[] b = new byte[65536];
                        int n;
                        while ((n = in.read(b)) > 0) out.write(b, 0, n);
                        s.fsync(out);
                    }
                    Intent i = new Intent(app, Result.class).putExtra("version", version);
                    int fl = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 31 ? PendingIntent.FLAG_MUTABLE : 0);
                    s.commit(PendingIntent.getBroadcast(app, 7, i, fl).getIntentSender());
                }
            } catch (Exception e) {
                installing = "";
                failed = version;
                message = "Update " + version + " fehlgeschlagen: " + e.getMessage();
            }
        }).start();
    }

    /** Ergebnis des Paket-Installers */
    public static class Result extends BroadcastReceiver {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            int st = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
            String ver = intent.getStringExtra("version");
            if (ver == null) ver = "";
            if (st == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                Intent c = intent.getParcelableExtra(Intent.EXTRA_INTENT);
                confirm = c;
                message = "Update " + ver + " bereit – bitte „Installieren“ bestätigen";
                if (c != null) {
                    try {
                        c.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                        ctx.startActivity(c);
                    } catch (Exception ignored) {
                        // aus dem Hintergrund nicht erlaubt: die App zeigt einen Knopf
                    }
                }
            } else if (st == PackageInstaller.STATUS_SUCCESS) {
                confirm = null;
                message = "";
            } else {
                confirm = null;
                installing = "";
                failed = ver;
                String m = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
                message = st == PackageInstaller.STATUS_FAILURE_ABORTED
                        ? "Update " + ver + " abgebrochen – über „Update installieren“ nachholen"
                        : "Update " + ver + " nicht installiert" + (m != null ? ": " + m : "");
            }
        }
    }

    /** nach dem Update: VPN wieder einschalten, wenn es vorher an war */
    public static class Replaced extends BroadcastReceiver {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            if (!Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction())) return;
            if (!KroneVpnService.prefs(ctx).getBoolean("on", false)) return;
            if (VpnService.prepare(ctx) != null) return;
            try {
                ctx.startService(new Intent(ctx, KroneVpnService.class));
            } catch (Exception ignored) {
                // Android erlaubt den Start aus dem Hintergrund nicht immer – "Durchgehend aktives VPN" startet es dann
            }
        }
    }
}
