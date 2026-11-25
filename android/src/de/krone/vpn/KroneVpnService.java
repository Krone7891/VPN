package de.krone.vpn;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.ProxyInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;

import java.io.File;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * VPN-Dienst: baut das Tunnel-Interface (alles IPv4 + IPv6 laeuft hindurch) und uebergibt es dem Rust-Kern.
 * Die App selbst ist vom Tunnel ausgenommen, damit ihre eigene Verbindung zum Server ueber WLAN/Mobilfunk geht.
 * Unterstuetzt "Immer aktives VPN" (Android startet den Dienst dann selbst mit dem gespeicherten Code).
 */
public class KroneVpnService extends VpnService {
    static final String ACTION_STOP = "de.krone.vpn.STOP";
    /** pausiert (vertrautes WLAN): trotzdem jetzt verbinden – bis zum naechsten Netzwechsel */
    static final String ACTION_JETZT = "de.krone.vpn.JETZT";
    /** Regeln geaendert (z. B. Apps am VPN vorbei): Tunnel neu aufbauen */
    static final String ACTION_NEU = "de.krone.vpn.NEU";
    /** automatisch schuetzen: im vertrauten Netz pausiert ("" = nicht pausiert, sonst Anzeige des Netzes) */
    static volatile String paused = "";
    private boolean override = false;
    /** nach einem App-Update aus dem Hintergrund gestartet (startForegroundService) */
    static final String EXTRA_AFTER_UPDATE = "nach_update";
    private static final int NOTIF_RESTART = 43;
    private static final int NOTIF_VPN = 45;
    static volatile long handle = 0;
    static volatile String lastError = "";

    private ConnectivityManager.NetworkCallback netCb;
    private Network lastNet;

    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("kronevpn", Context.MODE_PRIVATE);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Absturz.install(this);
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            prefs(this).edit().putBoolean("on", false).apply();
            stopTunnel(false);
            stopSelf();
            return START_NOT_STICKY;
        }
        String code = prefs(this).getString("code", null);
        if (code == null) {
            lastError = "Noch kein Verbindungscode – bitte in der App unter „Profil hinzufügen“ einfügen.";
            stopSelf();
            return START_NOT_STICKY;
        }
        boolean afterUpdate = intent != null && intent.getBooleanExtra(EXTRA_AFTER_UPDATE, false);
        if (afterUpdate) {
            // Android verlangt bei startForegroundService sofort eine Benachrichtigung; sobald der Tunnel steht,
            // haelt das System den VPN-Dienst selbst am Leben und die Benachrichtigung verschwindet wieder
            try {
                startForeground(NOTIF_RESTART, Updater.notice(this, "KroneVPN wurde aktualisiert", "Verbinde neu …", false));
            } catch (Exception ignored) {
            }
        }
        if (intent != null && ACTION_JETZT.equals(intent.getAction())) override = true;
        if (intent != null && ACTION_NEU.equals(intent.getAction()) && handle != 0) {
            // neue Regeln (Apps am VPN vorbei): Tunnel neu aufbauen
            stopTunnel(true);
            if (handle == 0) startTunnel(code);
            if (handle != 0) ongoing();
            evaluateLater(1500);
            return START_STICKY;
        }
        if (handle == 0) {
            // automatisch schuetzen: im vertrauten WLAN gar nicht erst verbinden, sondern pausieren
            if (!override && !Schutz.sollSchuetzen(this)) {
                pause();
                return START_STICKY;
            }
            paused = "";
            startTunnel(code);
        }
        // dauerhafte Benachrichtigung, solange das VPN laeuft: zeigt offen, dass verbunden ist und ob der Standort
        // geteilt wird (nichts laeuft versteckt im Hintergrund)
        if (handle != 0) ongoing();
        else if (afterUpdate) {
            try {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } catch (Exception ignored) {
            }
        }
        return START_STICKY;
    }

    private synchronized void startTunnel(String code) {
        try {
            JSONObject c = new JSONObject(Native.parse(code));
            if (c.has("error")) {
                lastError = c.getString("error");
                stopSelf();
                return;
            }
            Builder b = new Builder();
            b.setSession(c.optString("title", "KroneVPN") + " – " + c.getString("name"));
            b.setMtu(c.getInt("mtu"));
            String[] a4 = c.getString("ip4").split("/");
            b.addAddress(a4[0], Integer.parseInt(a4[1]));
            b.addRoute("0.0.0.0", 0);
            String ip6 = c.optString("ip6", "");
            if (!ip6.isEmpty()) {
                String[] a6 = ip6.split("/");
                b.addAddress(a6[0], Integer.parseInt(a6[1]));
                b.addRoute("::", 0);
            }
            // ohne IPv6 im Tunnel blockiert Android IPv6 automatisch (kein Datenleck daran vorbei)
            JSONArray dns = c.getJSONArray("dns");
            for (int i = 0; i < dns.length(); i++) {
                String d = dns.getString(i);
                if (d.contains(":") && ip6.isEmpty()) continue;
                b.addDnsServer(d);
            }
            b.addDisallowedApplication(getPackageName());
            // Apps am VPN vorbei (in der App unter „Schutz“ gewaehlt)
            for (String pkg : Schutz.apps(this)) {
                try {
                    if (!pkg.equals(getPackageName())) b.addDisallowedApplication(pkg);
                } catch (Exception ignored) {
                    // App deinstalliert
                }
            }
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            Intent open = new Intent(this, MainActivity.class);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE));
            ParcelFileDescriptor pfd = b.establish();
            if (pfd == null) {
                lastError = "Android hat die VPN-Erlaubnis entzogen (anderes VPN aktiv?). In der App auf den Knopf tippen und die Abfrage mit „OK“ bestätigen.";
                stopSelf();
                return;
            }
            int fd = pfd.detachFd();
            File upd = new File(getCacheDir(), "update");
            new File(upd, "update.apk").delete(); // Rest eines frueheren Updates
            Native.cipher(MainActivity.cipherPref(this));
            Native.logoDir(Logo.dir(this).getAbsolutePath());
            logoId = Logo.id(this);
            handle = Native.start(fd, code, systemProxy(), upd.getAbsolutePath());
            if (handle == 0) {
                lastError = "Der VPN-Kern konnte nicht starten. Bitte den Verbindungscode prüfen oder die App neu öffnen.";
                stopSelf();
                return;
            }
            lastError = "";
            prefs(this).edit().putBoolean("on", true).apply();
            // Notbremse des Systems ("Durchgehend aktives VPN" + "Verbindungen ohne VPN blockieren") – fuer die Anzeige
            if (Build.VERSION.SDK_INT >= 29) {
                try {
                    Schutz.alwaysOn = isAlwaysOn();
                    Schutz.lockdown = isLockdownEnabled();
                    Schutz.bekannt = true;
                } catch (Exception ignored) {
                }
            }
            watchNetwork();
            timer.removeCallbacks(checkUpdate);
            timer.postDelayed(checkUpdate, 5000);
            timer.removeCallbacks(reportLoc);
            timer.postDelayed(reportLoc, 4000);
            lastLocate = 0;
            Standort.listenPassive(this, true);
        } catch (Exception e) {
            lastError = "Das VPN konnte nicht starten (" + e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()) + "). Bitte nochmal verbinden – sonst Handy neu starten.";
            stopSelf();
        }
    }

    private final Handler timer = new Handler(Looper.getMainLooper());
    private long lastLocate = 0;
    /** Kennung des Logos beim letzten Nachsehen – neues Logo: Benachrichtigung + Verknuepfung erneuern */
    private String logoId = "";

    /** alle 5 s: liegt eine fertig geladene, gepruefte neue Version bereit? -> installieren */
    private final Runnable checkUpdate = new Runnable() {
        @Override
        public void run() {
            long h = handle;
            if (h == 0) return;
            try {
                JSONObject j = new JSONObject(Native.status(h));
                String f = j.optString("update_file", "");
                if (!f.isEmpty()) Updater.install(KroneVpnService.this, f, j.optString("update_version", ""), false);
                // "Jetzt orten" auf der Admin-Seite: frischen Standort holen und melden (still, ohne Anzeige)
                // Absturz-Protokolle: neue hochladen, bestaetigte loeschen
                Absturz.confirmed(KroneVpnService.this, j);
                Absturz.upload(KroneVpnService.this);
                long loc = j.optLong("locate", 0);
                if (loc > lastLocate) {
                    lastLocate = loc;
                    Standort.locateNow(KroneVpnService.this);
                }
                String lid = Logo.id(KroneVpnService.this);
                if (!lid.equals(logoId)) {
                    logoId = lid;
                    ongoing();
                    Logo.refreshShortcut(KroneVpnService.this, vpnTitle());
                }
            } catch (Exception ignored) {
            }
            timer.postDelayed(this, 5000);
        }
    };

    /** "Standort teilen" (nur wenn in der App eingeschaltet): WLAN-Name + Standort alle 5 Minuten an den Server */
    private final Runnable reportLoc = new Runnable() {
        @Override
        public void run() {
            if (handle == 0) return;
            Standort.report(KroneVpnService.this);
            timer.postDelayed(this, 5 * 60_000L);
        }
    };

    /** Proxy des Netzes (z. B. Firmen-WLAN mit Sophos-Proxy) als "host:port" */
    private String systemProxy() {
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            ProxyInfo p = cm.getDefaultProxy();
            if (p != null && p.getHost() != null && !p.getHost().isEmpty() && p.getPort() > 0) {
                return p.getHost() + ":" + p.getPort();
            }
        } catch (Exception ignored) {
        }
        return "";
    }

    /** Netzwechsel (WLAN <-> Mobil): sofort neu verbinden statt auf Zeitueberschreitung zu warten */
    private void watchNetwork() {
        if (netCb != null) return;
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        netCb = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                if (lastNet != null && !lastNet.equals(network)) {
                    override = false;
                    if (handle != 0) {
                        Native.reconnect(handle);
                        // anderes Netz (z. B. anderes WLAN): Standort gleich neu melden
                        timer.postDelayed(() -> Standort.report(KroneVpnService.this), 5000);
                    }
                }
                lastNet = network;
                evaluateLater(2000);
            }

            @Override
            public void onCapabilitiesChanged(Network network, android.net.NetworkCapabilities nc) {
                // anderes WLAN ohne Netzwechsel-Meldung (z. B. Roaming): nachsehen
                evaluateLater(2500);
            }
        };
        try {
            cm.registerDefaultNetworkCallback(netCb);
        } catch (Exception e) {
            netCb = null;
        }
    }

    /** Benachrichtigung "KroneVPN verbunden" (mit Hinweis auf Standort-Teilen und Knopf zum Trennen) */
    /** Name des VPN aus dem Verbindungscode */
    String vpnTitle() {
        try {
            return new JSONObject(Native.parse(prefs(this).getString("code", ""))).optString("title", "KroneVPN");
        } catch (Exception e) {
            return "KroneVPN";
        }
    }

    void ongoing() {
        try {
            String title = vpnTitle() + " ist an";
            String text = Standort.enabled(this) && Standort.permitted(this)
                    ? "Standort wird mit deinem eigenen Server geteilt (abschaltbar in der App)"
                    : "Datenverkehr läuft verschlüsselt über deinen Server";
            android.app.NotificationManager nm = getSystemService(android.app.NotificationManager.class);
            nm.createNotificationChannel(new android.app.NotificationChannel("vpn", "KroneVPN", android.app.NotificationManager.IMPORTANCE_LOW));
            PendingIntent open = PendingIntent.getActivity(this, 10, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
            PendingIntent stop = PendingIntent.getService(this, 11, new Intent(this, KroneVpnService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
            android.app.Notification n = new android.app.Notification.Builder(this, "vpn")
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    .setContentTitle(title)
                    .setContentText(text)
                    .setLargeIcon(Logo.bitmap(this))
                    .setStyle(new android.app.Notification.BigTextStyle().bigText(text))
                    .setContentIntent(open)
                    .addAction(new android.app.Notification.Action.Builder(null, "Trennen", stop).build())
                    .setOngoing(true)
                    .setShowWhen(false)
                    .build();
            startForeground(NOTIF_VPN, n);
        } catch (Exception ignored) {
            // z. B. Start durch "Durchgehend aktives VPN" im Hintergrund: dann ohne eigene Benachrichtigung
        }
    }

    /** Tunnel beenden. `pausieren`: Dienst, Netz-Beobachtung und Benachrichtigung bleiben (automatisch schuetzen) */
    private synchronized void stopTunnel(boolean pausieren) {
        if (!pausieren) {
            paused = "";
            timer.removeCallbacks(evaluate);
            try {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } catch (Exception ignored) {
            }
        }
        timer.removeCallbacks(checkUpdate);
        timer.removeCallbacks(reportLoc);
        Standort.listenPassive(this, false);
        if (netCb != null && !pausieren) {
            try {
                getSystemService(ConnectivityManager.class).unregisterNetworkCallback(netCb);
            } catch (Exception ignored) {
            }
            netCb = null;
        }
        long h = handle;
        handle = 0;
        if (h != 0) Native.stop(h);
    }

    @Override
    public void onRevoke() {
        prefs(this).edit().putBoolean("on", false).apply();
        stopTunnel(false);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopTunnel(false);
        super.onDestroy();
    }

    // ------------------------------------------------------------------------------------------ automatisch schuetzen

    private void evaluateLater(long ms) {
        timer.removeCallbacks(evaluate);
        timer.postDelayed(evaluate, ms);
    }

    /** Netz geaendert: im vertrauten WLAN pausieren, sonst (wieder) verbinden */
    private final Runnable evaluate = new Runnable() {
        @Override
        public void run() {
            if (!prefs(KroneVpnService.this).getBoolean("on", false)) return;
            boolean soll = override || Schutz.sollSchuetzen(KroneVpnService.this);
            String code = prefs(KroneVpnService.this).getString("code", null);
            if (soll && handle == 0 && !paused.isEmpty() && code != null) {
                paused = "";
                startTunnel(code);
                if (handle != 0) ongoing();
            } else if (!soll && handle != 0) {
                stopTunnel(true);
                pause();
            } else if (!soll && !paused.isEmpty()) {
                pause();
            }
        }
    };

    /** pausiert im vertrauten Netz: Dienst bleibt (sichtbar), verbindet von selbst in fremden Netzen */
    private void pause() {
        String w = Schutz.wlan(this);
        paused = w.isEmpty() ? "vertrautes Netz" : "WLAN „" + w + "“";
        prefs(this).edit().putBoolean("on", true).apply();
        watchNetwork();
        try {
            android.app.NotificationManager nm = getSystemService(android.app.NotificationManager.class);
            nm.createNotificationChannel(new android.app.NotificationChannel("vpn", "KroneVPN", android.app.NotificationManager.IMPORTANCE_LOW));
            PendingIntent open = PendingIntent.getActivity(this, 10, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
            PendingIntent jetzt = PendingIntent.getService(this, 12, new Intent(this, KroneVpnService.class).setAction(ACTION_JETZT), PendingIntent.FLAG_IMMUTABLE);
            PendingIntent stop = PendingIntent.getService(this, 11, new Intent(this, KroneVpnService.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
            String text = "Vertrautes " + paused.replace("WLAN „", "WLAN „") + " – in fremden Netzen verbindet es sich von selbst";
            android.app.Notification n = new android.app.Notification.Builder(this, "vpn")
                    .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                    .setContentTitle(vpnTitle() + " pausiert")
                    .setContentText(text)
                    .setLargeIcon(Logo.bitmap(this))
                    .setStyle(new android.app.Notification.BigTextStyle().bigText(text))
                    .setContentIntent(open)
                    .addAction(new android.app.Notification.Action.Builder(null, "Jetzt verbinden", jetzt).build())
                    .addAction(new android.app.Notification.Action.Builder(null, "Aus", stop).build())
                    .setOngoing(true)
                    .setShowWhen(false)
                    .build();
            startForeground(NOTIF_VPN, n);
        } catch (Exception ignored) {
        }
    }
}
