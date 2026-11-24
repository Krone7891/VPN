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
import android.os.ParcelFileDescriptor;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * VPN-Dienst: baut das Tunnel-Interface (alles IPv4 + IPv6 laeuft hindurch) und uebergibt es dem Rust-Kern.
 * Die App selbst ist vom Tunnel ausgenommen, damit ihre eigene Verbindung zum Server ueber WLAN/Mobilfunk geht.
 * Unterstuetzt "Immer aktives VPN" (Android startet den Dienst dann selbst mit dem gespeicherten Code).
 */
public class KroneVpnService extends VpnService {
    static final String ACTION_STOP = "de.krone.vpn.STOP";
    static volatile long handle = 0;
    static volatile String lastError = "";

    private ConnectivityManager.NetworkCallback netCb;
    private Network lastNet;

    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("kronevpn", Context.MODE_PRIVATE);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            prefs(this).edit().putBoolean("on", false).apply();
            stopTunnel();
            stopSelf();
            return START_NOT_STICKY;
        }
        String code = prefs(this).getString("code", null);
        if (code == null) {
            lastError = "Kein Verbindungscode gespeichert";
            stopSelf();
            return START_NOT_STICKY;
        }
        if (handle == 0) startTunnel(code);
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
                lastError = "Keine VPN-Berechtigung – bitte in der App auf Verbinden tippen";
                stopSelf();
                return;
            }
            int fd = pfd.detachFd();
            handle = Native.start(fd, code, systemProxy());
            if (handle == 0) {
                lastError = "Tunnel konnte nicht gestartet werden";
                stopSelf();
                return;
            }
            lastError = "";
            prefs(this).edit().putBoolean("on", true).apply();
            watchNetwork();
        } catch (Exception e) {
            lastError = "Fehler: " + e.getMessage();
            stopSelf();
        }
    }

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
                if (lastNet != null && !lastNet.equals(network) && handle != 0) Native.reconnect(handle);
                lastNet = network;
            }
        };
        try {
            cm.registerDefaultNetworkCallback(netCb);
        } catch (Exception e) {
            netCb = null;
        }
    }

    private synchronized void stopTunnel() {
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
