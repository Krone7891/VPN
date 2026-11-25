package de.krone.vpn;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Schutz-Regeln der App (gleiches Format wie am PC, Entscheidung im Rust-Kern: kvpn::regeln):
 *   * Notbremse: unter Android die System-Einstellung "Durchgehend aktives VPN" + "Verbindungen ohne VPN blockieren"
 *     (die App kann sie nur anzeigen und dorthin fuehren – einschalten darf nur der Nutzer)
 *   * automatisch schuetzen: in fremden WLANs und im Mobilfunk verbinden, in vertrauten WLANs pausieren
 *   * Apps am VPN vorbei
 */
final class Schutz {
    /** vom VPN-Dienst nach dem Verbinden gesetzt (VpnService.isAlwaysOn / isLockdownEnabled, ab Android 10) */
    static volatile boolean alwaysOn = false;
    static volatile boolean lockdown = false;
    static volatile boolean bekannt = false;

    private Schutz() {
    }

    static JSONObject regeln(Context c) {
        try {
            return new JSONObject(KroneVpnService.prefs(c).getString("regeln", "{}"));
        } catch (Exception e) {
            return new JSONObject();
        }
    }

    static void save(Context c, JSONObject r) {
        KroneVpnService.prefs(c).edit().putString("regeln", r.toString()).apply();
    }

    static boolean auto(Context c) {
        return regeln(c).optBoolean("auto", false);
    }

    static List<String> list(JSONObject r, String key) {
        List<String> l = new ArrayList<>();
        JSONArray a = r.optJSONArray(key);
        if (a != null) for (int i = 0; i < a.length(); i++) l.add(a.optString(i));
        return l;
    }

    static void putList(JSONObject r, String key, List<String> l) {
        try {
            r.put(key, new JSONArray(l));
        } catch (Exception ignored) {
        }
    }

    /** Apps, die am VPN vorbei gehen (Paketnamen) */
    static List<String> apps(Context c) {
        return list(regeln(c), "apps");
    }

    /** Name des verbundenen WLANs ("" = kein WLAN oder Name nicht lesbar – dafuer braucht Android den Standort) */
    @SuppressWarnings("deprecation")
    static String wlan(Context c) {
        try {
            ConnectivityManager cm = c.getSystemService(ConnectivityManager.class);
            NetworkCapabilities nc = cm.getNetworkCapabilities(cm.getActiveNetwork());
            // mit laufendem VPN ist das aktive Netz fuer diese App das echte (die App ist vom Tunnel ausgenommen)
            if (nc == null || !nc.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return "";
            WifiManager wm = c.getApplicationContext().getSystemService(WifiManager.class);
            WifiInfo wi = wm == null ? null : wm.getConnectionInfo();
            String s = wi == null ? null : wi.getSSID();
            if (s == null || s.contains("unknown ssid")) return "";
            if (s.startsWith("\"") && s.endsWith("\"") && s.length() > 2) s = s.substring(1, s.length() - 1);
            return s;
        } catch (Exception e) {
            return "";
        }
    }

    static boolean online(Context c) {
        try {
            ConnectivityManager cm = c.getSystemService(ConnectivityManager.class);
            return cm.getActiveNetwork() != null;
        } catch (Exception e) {
            return true;
        }
    }

    /**
     * soll das VPN gerade laufen? Ohne "automatisch schuetzen" immer. Mit Notbremse des Systems nie pausieren
     * (sonst gaebe es im vertrauten WLAN gar kein Internet).
     */
    static boolean sollSchuetzen(Context c) {
        JSONObject r = regeln(c);
        if (!r.optBoolean("auto", false) || lockdown) return true;
        try {
            return Native.schuetzen(r.toString(), wlan(c), online(c));
        } catch (Throwable t) {
            return true;
        }
    }

    /** aktuelles WLAN als vertraut merken; Ergebnis: Name oder "" (kein WLAN/Name nicht lesbar) */
    static String vertrauen(Context c) {
        String w = wlan(c);
        if (w.isEmpty()) return "";
        JSONObject r = regeln(c);
        List<String> v = list(r, "vertraut");
        if (!v.contains(w)) v.add(w);
        putList(r, "vertraut", v);
        save(c, r);
        return w;
    }
}
