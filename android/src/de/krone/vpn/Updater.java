package de.krone.vpn;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.provider.Settings;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Automatische Aktualisierung: Der Rust-Kern laedt die neue APK ueber die VPN-Verbindung, prueft Signatur und
 * Pruefsumme und legt sie ab. Hier wird sie mit dem Paket-Installer von Android eingespielt.
 * Android prueft zusaetzlich, dass die neue APK mit demselben Schluessel signiert ist wie die installierte.
 * Android fragt jedes Mal nach ("Installieren?") – bewusst ohne stille Updates (Google Play Protect).
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
    /** Paket-Installer-Sitzung, die auf Bestaetigung wartet */
    static volatile int session = -1;
    /** sichtbare App-Oberflaeche (dann darf die Rueckfrage sofort geoeffnet werden) */
    static volatile Activity visible;
    /** wann die Rueckfrage zuletzt geoeffnet bzw. abgebrochen wurde (keine Endlosschleife) */
    static volatile long shownAt, abortedAt, startedAt;
    /** Erlaubnis "Unbekannte Apps installieren" wurde gerade angefragt */
    static volatile boolean askedPermission;

    static final String ACTION_INSTALL = "de.krone.vpn.INSTALL_UPDATE";

    // ---------------------------------------------------------------- Samsung "Automatische Sperre" (Auto Blocker)
    // Ab One UI 6 (Android 14) laesst die "Automatische Sperre" nur Apps aus Galaxy Store/Play Store zu und blockiert
    // damit auch das Update aus der App. Vor dem Update einmal erklaeren und zur Einstellung fuehren; danach geht es
    // von selbst weiter. "Ist schon aus" merkt sich die App – bis ein Update doch blockiert wird.

    /** was nach der Rueckkehr aus den Einstellungen weiterlaufen soll */
    private static volatile Runnable nachSperre;
    private static volatile boolean sperreOffen;
    /** "Später" gewaehlt (dann nicht alle paar Sekunden wieder fragen) */
    private static volatile long spaeterAt;
    /** zuletzt installierte Datei (zum Wiederholen nach einer Sperre) */
    private static volatile String letzteDatei = "";

    static boolean samsungSperreMoeglich(Context c) {
        return "samsung".equalsIgnoreCase(Build.MANUFACTURER) && Build.VERSION.SDK_INT >= 34
                && !KroneVpnService.prefs(c).getBoolean("autosperre_ok", false);
    }

    /** Erklaerung + "Einstellungen öffnen". weiter = Update danach fortsetzen */
    static void sperreDialog(Activity a, Runnable weiter) {
        if (sperreOffen || a.isFinishing()) return;
        sperreOffen = true;
        message = "Update wartet – Samsung „Automatische Sperre“ kurz ausschalten";
        new android.app.AlertDialog.Builder(a)
                .setTitle("Update: „Automatische Sperre“ ausschalten")
                .setMessage("Die „Automatische Sperre“ von Samsung erlaubt Apps nur aus dem Galaxy Store und Play Store – "
                        + "deshalb blockiert sie das Update von KroneVPN.\n\n"
                        + "1. „Einstellungen öffnen“ tippen (Sicherheit und Datenschutz)\n"
                        + "2. „Automatische Sperre“ antippen und ausschalten\n"
                        + "3. Zurück zur App – das Update startet von selbst\n\n"
                        + "Danach kannst du sie wieder einschalten (beim nächsten Update fragt die App wieder).")
                .setPositiveButton("Einstellungen öffnen", (d, w) -> {
                    KroneVpnService.prefs(a).edit().putBoolean("autosperre_ok", true).apply();
                    nachSperre = weiter;
                    oeffneSperre(a);
                })
                .setNeutralButton("Ist schon aus", (d, w) -> {
                    KroneVpnService.prefs(a).edit().putBoolean("autosperre_ok", true).apply();
                    weiter.run();
                })
                .setNegativeButton("Später", (d, w) -> spaeterAt = System.currentTimeMillis())
                .setOnDismissListener(d -> sperreOffen = false)
                .show();
    }

    /** Einstellungen bei "Sicherheit und Datenschutz" oeffnen (dort steht die "Automatische Sperre") */
    private static void oeffneSperre(Activity a) {
        Toast.makeText(a, "„Automatische Sperre“ antippen → ausschalten → zurück zur App", Toast.LENGTH_LONG).show();
        for (String act : new String[]{Settings.ACTION_SECURITY_SETTINGS, Settings.ACTION_SETTINGS}) {
            try {
                a.startActivity(new Intent(act));
                return;
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Hinweis in der Benachrichtigungsleiste. Noetig, weil Android aus dem Hintergrund keine Rueckfrage oeffnen darf:
     * Wurde die App von Hand (Browser/Dateien) installiert, muss Android das erste Update einmal bestaetigen lassen –
     * danach aktualisiert sie sich (ab Android 12) ohne Rueckfrage.
     */
    /** einfache Benachrichtigung (leiser Kanal "KroneVPN"), z. B. fuer den Neustart nach einem Update */
    static Notification notice(Context ctx, String title, String text, boolean install) {
        NotificationManager nm = ctx.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel("vpn", "KroneVPN", NotificationManager.IMPORTANCE_LOW));
        Intent open = new Intent(ctx, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (install) open.setAction(ACTION_INSTALL);
        PendingIntent pi = PendingIntent.getActivity(ctx, 9, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(ctx, "vpn")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle(title)
                .setContentText(text)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
    }

    static void notifyUser(Context ctx, String title, String text, boolean install) {
        try {
            SharedPreferences pr = KroneVpnService.prefs(ctx);
            String key = title + "|" + text;
            long now = System.currentTimeMillis();
            if (key.equals(pr.getString("upd_note", "")) && now - pr.getLong("upd_note_t", 0) < 6 * 3600_000L) return;
            pr.edit().putString("upd_note", key).putLong("upd_note_t", now).apply();
            NotificationManager nm = ctx.getSystemService(NotificationManager.class);
            nm.createNotificationChannel(new NotificationChannel("updates", "App-Updates", NotificationManager.IMPORTANCE_HIGH));
            Intent open = new Intent(ctx, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            if (install) open.setAction(ACTION_INSTALL);
            PendingIntent pi = PendingIntent.getActivity(ctx, 8, open, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
            Notification n = new Notification.Builder(ctx, "updates")
                    .setSmallIcon(android.R.drawable.stat_sys_download_done)
                    .setContentTitle(title)
                    .setContentText(text)
                    .setContentIntent(pi)
                    .setAutoCancel(true)
                    .build();
            nm.notify(42, n);
        } catch (Exception ignored) {
            // ohne Erlaubnis fuer Benachrichtigungen: die App zeigt den Hinweis beim Oeffnen
        }
    }

    static void install(Context ctx, String path, String version, boolean byUser) {
        if (version.isEmpty() || version.equals(installing) || (!byUser && version.equals(failed))) return;
        File apk = new File(path);
        if (!apk.isFile()) return;
        // Samsung: vorher zur "Automatischen Sperre" fuehren (nur mit sichtbarer App; im Hintergrund wird es versucht
        // und bei einer Sperre erscheint ein Hinweis zum Antippen)
        letzteDatei = path;
        if (nachSperre != null || (!byUser && System.currentTimeMillis() - spaeterAt < 600_000L && samsungSperreMoeglich(ctx))) return;
        Activity sichtbar = visible;
        if (sichtbar != null && samsungSperreMoeglich(ctx)) {
            sichtbar.runOnUiThread(() -> sperreDialog(sichtbar, () -> install(sichtbar, path, version, true)));
            return;
        }
        installing = version;
        startedAt = System.currentTimeMillis();
        failed = "";
        message = "Update " + version + " wird installiert …";
        final Context app = ctx.getApplicationContext();
        new Thread(() -> {
            try {
                PackageInstaller pi = app.getPackageManager().getPackageInstaller();
                // alte, haengengebliebene Sitzungen dieser App verwerfen (sonst stoeren sie sich gegenseitig)
                for (PackageInstaller.SessionInfo old : pi.getMySessions()) {
                    try {
                        pi.abandonSession(old.getSessionId());
                    } catch (Exception ignored) {
                    }
                }
                confirm = null;
                PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
                p.setAppPackageName(app.getPackageName());
                p.setSize(apk.length());
                // ab Android 14: diese App wird "Update-Besitzer" – spaetere Updates gehen dann sicher ohne Rueckfrage
                int id = pi.createSession(p);
                session = id;
                try (PackageInstaller.Session s = pi.openSession(id)) {
                    try (InputStream in = new FileInputStream(apk); OutputStream out = s.openWrite("update.apk", 0, apk.length())) {
                        byte[] b = new byte[65536];
                        int n;
                        while ((n = in.read(b)) > 0) out.write(b, 0, n);
                        s.fsync(out);
                    }
                    // war das VPN an? Dann nach dem Einspielen von selbst wieder verbinden – auch wenn Android das VPN
                    // beim Austausch der App kurz entzieht (onRevoke setzt "on" auf aus)
                    if (KroneVpnService.handle != 0 || KroneVpnService.prefs(app).getBoolean("on", false))
                        KroneVpnService.prefs(app).edit().putLong("resume_after_update", System.currentTimeMillis()).apply();
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

    /** Ist die wartende Sitzung noch gueltig? (eine abgebrochene laesst sich nicht wieder oeffnen) */
    static boolean sessionAlive(Context ctx) {
        int id = session;
        if (id < 0) return false;
        try {
            PackageInstaller.SessionInfo i = ctx.getPackageManager().getPackageInstaller().getSessionInfo(id);
            return i != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Rueckfrage von Android ("Installieren") oeffnen – in einer EIGENEN Aufgabe (NEW_TASK): Sonst liegt sie im
     * Stapel der App, und sobald die App wieder geoeffnet wird (singleTask), schliesst Android sie = "abgebrochen".
     */
    static boolean showConfirm(Activity a) {
        Intent c = confirm;
        if (c == null) return false;
        if (!sessionAlive(a)) {
            confirm = null;
            return false;
        }
        if (Build.VERSION.SDK_INT >= 26 && !a.getPackageManager().canRequestPackageInstalls()) {
            // erst die Erlaubnis "Unbekannte Apps installieren" fuer diese App – danach geht es von selbst weiter
            Toast.makeText(a, "Bitte „Dieser Quelle vertrauen“ / „Zulassen“ einschalten und zurückgehen – dann kommt das Update", Toast.LENGTH_LONG).show();
            try {
                a.startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + a.getPackageName())));
                askedPermission = true;
                return true;
            } catch (Exception ignored) {
            }
        }
        try {
            a.startActivity(new Intent(c).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));
            shownAt = System.currentTimeMillis();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * App kommt in den Vordergrund: wartet ein Update auf Bestaetigung, Rueckfrage gleich zeigen; wurde es vorher
     * abgebrochen (oder die App neu gestartet), es neu anstossen. Nie in einer Schleife (hoechstens alle 20 s).
     */
    static void onForeground(Activity a, String file, String version) {
        long now = System.currentTimeMillis();
        // zurueck aus den Einstellungen ("Automatische Sperre" aus): Update jetzt fortsetzen
        Runnable weiter = nachSperre;
        if (weiter != null) {
            nachSperre = null;
            installing = "";
            weiter.run();
            return;
        }
        boolean granted = askedPermission && (Build.VERSION.SDK_INT < 26 || a.getPackageManager().canRequestPackageInstalls());
        if (askedPermission && !granted) {
            // Erlaubnis nicht erteilt: jetzt nicht weiter draengeln (beim naechsten Oeffnen wieder)
            askedPermission = false;
            shownAt = now;
            return;
        }
        askedPermission = false;
        if (!granted && (now - shownAt < 20_000 || now - abortedAt < 20_000)) return;
        if (confirm != null && showConfirm(a)) return;
        if (!file.isEmpty() && !version.isEmpty() && confirm == null && !sessionAlive(a) && now - startedAt > 30_000) {
            installing = "";
            install(a, file, version, true);
        }
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
                // App sichtbar: Rueckfrage sofort zeigen. Aus dem Hintergrund geht das nicht -> Benachrichtigung + Knopf
                Activity a = visible;
                if (a == null || !showConfirm(a))
                    notifyUser(ctx, "Update " + ver + " bereit", "Tippen und „Installieren“ bestätigen (nur einmal nötig)", true);
            } else if (st == PackageInstaller.STATUS_SUCCESS) {
                confirm = null;
                session = -1;
                message = "";
                ((NotificationManager) ctx.getSystemService(NotificationManager.class)).cancel(42);
            } else {
                confirm = null;
                session = -1;
                installing = "";
                failed = ver;
                String m = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE);
                if (st == PackageInstaller.STATUS_FAILURE_ABORTED) abortedAt = System.currentTimeMillis();
                // Samsung "Automatische Sperre" hat blockiert: beim naechsten Versuch wieder erklaeren + hinfuehren
                String ml = m == null ? "" : m.toLowerCase(java.util.Locale.ROOT);
                if ("samsung".equalsIgnoreCase(Build.MANUFACTURER) && Build.VERSION.SDK_INT >= 34
                        && (st == PackageInstaller.STATUS_FAILURE_BLOCKED || ml.contains("block") || ml.contains("sperre"))) {
                    KroneVpnService.prefs(ctx).edit().putBoolean("autosperre_ok", false).apply();
                    failed = "";
                    message = "Update " + ver + " von Samsungs „Automatischer Sperre“ blockiert – „Update installieren“ tippen";
                    Activity a = visible;
                    String datei = letzteDatei, version = ver;
                    if (a != null && !datei.isEmpty()) a.runOnUiThread(() -> sperreDialog(a, () -> install(a, datei, version, true)));
                    else notifyUser(ctx, "Update " + ver + " blockiert", "Tippen: Samsungs „Automatische Sperre“ kurz ausschalten", true);
                    return;
                }
                message = st == PackageInstaller.STATUS_FAILURE_ABORTED
                        ? "Update " + ver + " nicht bestätigt – kommt beim nächsten Öffnen der App wieder (oder jetzt: „Update installieren“)"
                        : "Update " + ver + " nicht installiert" + (m != null ? ": " + m : "");
                if (st != PackageInstaller.STATUS_FAILURE_ABORTED) notifyUser(ctx, "Update " + ver + " nicht installiert", m != null ? m : "Details in der App", false);
            }
        }
    }

    /** nach dem Update: VPN wieder einschalten, wenn es vorher an war */
    public static class Replaced extends BroadcastReceiver {
        @Override
        public void onReceive(Context ctx, Intent intent) {
            if (!Intent.ACTION_MY_PACKAGE_REPLACED.equals(intent.getAction())) return;
            installing = "";
            ((NotificationManager) ctx.getSystemService(NotificationManager.class)).cancel(42);
            long resume = KroneVpnService.prefs(ctx).getLong("resume_after_update", 0);
            KroneVpnService.prefs(ctx).edit().remove("resume_after_update").apply();
            // nur wenn das VPN vorher an war (der Merker wird beim Trennen geloescht; Bestaetigen kann etwas dauern)
            boolean wasOn = KroneVpnService.prefs(ctx).getBoolean("on", false) || (resume > 0 && System.currentTimeMillis() - resume < 24 * 3600_000L);
            if (!wasOn) return;
            if (VpnService.prepare(ctx) != null) {
                // Erlaubnis fehlt (sehr selten nach einem Update): Hinweis zum Antippen
                notifyUser(ctx, "KroneVPN wurde aktualisiert", "Tippen, um wieder zu verbinden", false);
                return;
            }
            // App mit dem Patch neu starten: VPN-Dienst wieder an. Aus dem Hintergrund geht das nur als
            // Vordergrund-Dienst (nach MY_PACKAGE_REPLACED ausdruecklich erlaubt) – startService() wuerde Android blockieren
            try {
                ctx.startForegroundService(new Intent(ctx, KroneVpnService.class).putExtra(KroneVpnService.EXTRA_AFTER_UPDATE, true));
            } catch (Exception e) {
                // blockiert (z. B. Energiesparmodus): Hinweis zum Antippen
                try {
                    PendingIntent pi = PendingIntent.getActivity(ctx, 0, new Intent(ctx, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
                    Notification n = new Notification.Builder(ctx, "updates")
                            .setSmallIcon(android.R.drawable.stat_sys_download_done)
                            .setContentTitle("KroneVPN wurde aktualisiert")
                            .setContentText("Tippen, um wieder zu verbinden")
                            .setContentIntent(pi)
                            .setAutoCancel(true)
                            .build();
                    ((NotificationManager) ctx.getSystemService(NotificationManager.class)).notify(44, n);
                } catch (Exception ignored) {
                }
            }
        }
    }
}
