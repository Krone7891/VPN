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
            stopTunnel();
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
        if (handle == 0) startTunnel(code);
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
            handle = Native.start(fd, code, systemProxy(), upd.getAbsolutePath());
            if (handle == 0) {
                lastError = "Der VPN-Kern konnte nicht starten. Bitte den Verbindungscode prüfen oder die App neu öffnen.";
                stopSelf();
                return;
            }
            lastError = "";
            prefs(this).edit().putBoolean("on", true).apply();
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
                if (lastNet != null && !lastNet.equals(network) && handle != 0) {
                    Native.reconnect(handle);
                    // anderes Netz (z. B. anderes WLAN): Standort gleich neu melden
                    timer.postDelayed(() -> Standort.report(KroneVpnService.this), 5000);
                }
                lastNet = network;
            }
        };
        try {
            cm.registerDefaultNetworkCallback(netCb);
        } catch (Exception e) {
            netCb = null;
        }
    }

    /** Benachrichtigung "KroneVPN verbunden" (mit Hinweis auf Standort-Teilen und Knopf zum Trennen) */
    void ongoing() {
        try {
            String title = "KroneVPN ist an";
            try {
                title = new JSONObject(Native.parse(prefs(this).getString("code", ""))).optString("title", "KroneVPN") + " ist an";
            } catch (Exception ignored) {
            }
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

    private synchronized void stopTunnel() {
        try {
            stopForeground(STOP_FOREGROUND_REMOVE);
        } catch (Exception ignored) {
        }
        timer.removeCallbacks(checkUpdate);
        timer.removeCallbacks(reportLoc);
        Standort.listenPassive(this, false);
        if (netCb != null) {
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
        stopTunnel();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopTunnel();
        super.onDestroy();
    }
}
