package de.krone.vpn;

import android.Manifest;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.location.Location;
import android.location.LocationManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * "Standort teilen" (Standard AN, in der App abschaltbar): meldet dem eigenen VPN-Server den WLAN-Namen (SSID/BSSID) und den
 * Standort des Handys (Android-Ortung: GPS, WLAN, Mobilfunk – mit Genauigkeit). Der Server zeigt das nur auf der
 * Admin-Seite. Ausschalten in der App schickt {"off":true}, dann loescht der Server den gespeicherten Stand.
 * Uebertragen wird ueber die verschluesselte VPN-Verbindung (REC_INFO), nicht an Dritte.
 */
final class Standort {
    private Standort() {}

    static final String PREF = "share_loc";
    private static volatile long lastFresh;

    static boolean enabled(Context c) {
        return KroneVpnService.prefs(c).getBoolean(PREF, true);
    }

    static boolean permitted(Context c) {
        return c.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
                || c.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED;
    }

    /** Ein-/Ausschalten (Ausschalten meldet dem Server sofort "aus") */
    static void set(Context c, boolean on) {
        KroneVpnService.prefs(c).edit().putBoolean(PREF, on).putBoolean("loc_sent_off", false).apply();
        report(c);
    }

    /** Kurzfassung fuer die App: was zuletzt geteilt wurde */
    static String summary(Context c) {
        SharedPreferences p = KroneVpnService.prefs(c);
        if (!enabled(c)) return "Aus – der Server sieht nur den ungefähren Ort deiner Internet-Adresse.";
        if (!permitted(c)) return "An, aber ohne Erlaubnis für den Standort – bitte erlauben.";
        String s = p.getString("loc_last", "");
        return s.isEmpty() ? "An – wird beim nächsten Verbinden gesendet." : "An – zuletzt geteilt: " + s;
    }

    /** aktuellen Stand an den Server melden (wenn eingeschaltet und verbunden) */
    static void report(Context ctx) {
        final Context c = ctx.getApplicationContext();
        long h = KroneVpnService.handle;
        if (h == 0) return;
        SharedPreferences p = KroneVpnService.prefs(c);
        if (!enabled(c)) {
            if (!p.getBoolean("loc_sent_off", false)) {
                Native.report(h, "{\"off\":true}");
                p.edit().putBoolean("loc_sent_off", true).putString("loc_last", "").apply();
            }
            return;
        }
        if (!permitted(c)) return;
        Location best = lastKnown(c);
        send(c, best);
        // aelter als 5 Minuten: frische Ortung anfordern (Android 11+), Ergebnis wird nachgeschickt
        long age = best == null ? Long.MAX_VALUE : System.currentTimeMillis() - best.getTime();
        if (age > 5 * 60_000L && Build.VERSION.SDK_INT >= 30 && System.currentTimeMillis() - lastFresh > 60_000L) {
            lastFresh = System.currentTimeMillis();
            try {
                LocationManager lm = c.getSystemService(LocationManager.class);
                String prov = Build.VERSION.SDK_INT >= 31 && lm.getAllProviders().contains(LocationManager.FUSED_PROVIDER)
                        ? LocationManager.FUSED_PROVIDER
                        : (lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER) ? LocationManager.NETWORK_PROVIDER : LocationManager.GPS_PROVIDER);
                lm.getCurrentLocation(prov, null, c.getMainExecutor(), loc -> {
                    if (loc != null) send(c, loc);
                });
            } catch (SecurityException | IllegalArgumentException ignored) {
            }
        }
    }

    /**
     * "Jetzt orten" von der Admin-Seite (z. B. Handy verlegt oder gestohlen): frischen, moeglichst genauen Standort
     * (GPS) holen und melden – still, ohne Anzeige. Nur wenn "Standort teilen" an ist.
     */
    static void locateNow(Context ctx) {
        final Context c = ctx.getApplicationContext();
        if (!enabled(c) || !permitted(c) || KroneVpnService.handle == 0) return;
        Location best = lastKnown(c);
        send(c, best); // sofort das Beste, was da ist (inkl. WLAN-Netze fuer die WLAN-Ortung)
        if (Build.VERSION.SDK_INT < 30) return;
        try {
            LocationManager lm = c.getSystemService(LocationManager.class);
            String prov = lm.isProviderEnabled(LocationManager.GPS_PROVIDER) ? LocationManager.GPS_PROVIDER
                    : (Build.VERSION.SDK_INT >= 31 && lm.getAllProviders().contains(LocationManager.FUSED_PROVIDER) ? LocationManager.FUSED_PROVIDER : LocationManager.NETWORK_PROVIDER);
            android.os.CancellationSignal cs = new android.os.CancellationSignal();
            new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(cs::cancel, 60_000L);
            lm.getCurrentLocation(prov, cs, c.getMainExecutor(), loc -> {
                if (loc != null) send(c, loc);
            });
        } catch (SecurityException | IllegalArgumentException ignored) {
        }
    }

    private static android.location.LocationListener passive;

    /**
     * Standort mitlesen, wenn ANDERE Apps ihn ohnehin abfragen (Karten, Wetter …): kostet keinen zusaetzlichen Strom
     * und haelt den Verlauf aktuell – auch, falls das Handy gestohlen wurde und jemand anderes es benutzt.
     */
    static synchronized void listenPassive(Context ctx, boolean on) {
        final Context c = ctx.getApplicationContext();
        LocationManager lm = c.getSystemService(LocationManager.class);
        if (lm == null) return;
        if (passive != null) {
            try {
                lm.removeUpdates(passive);
            } catch (Exception ignored) {
            }
            passive = null;
        }
        if (!on || !enabled(c) || !permitted(c)) return;
        passive = loc -> {
            if (loc == null || KroneVpnService.handle == 0) return;
            // hoechstens jede Minute, und nur genaue Standorte (GPS/Fused), keine groben Funkzellen
            if (System.currentTimeMillis() - lastPassive < 60_000L) return;
            if (loc.hasAccuracy() && loc.getAccuracy() > 200) return;
            lastPassive = System.currentTimeMillis();
            send(c, loc, "passive");
        };
        try {
            lm.requestLocationUpdates(LocationManager.PASSIVE_PROVIDER, 60_000L, 30f, passive, android.os.Looper.getMainLooper());
        } catch (SecurityException | IllegalArgumentException e) {
            passive = null;
        }
    }

    private static volatile long lastPassive;

    private static Location lastKnown(Context c) {
        Location best = null;
        try {
            LocationManager lm = c.getSystemService(LocationManager.class);
            List<String> provs = lm.getProviders(true);
            for (String pr : provs) {
                Location l = lm.getLastKnownLocation(pr);
                if (l != null && (best == null || l.getTime() > best.getTime())) best = l;
            }
        } catch (SecurityException ignored) {
        }
        return best;
    }

    private static void send(Context c, Location loc) {
        send(c, loc, null);
    }

    @SuppressWarnings("deprecation")
    private static void send(Context c, Location loc, String src) {
        long h = KroneVpnService.handle;
        if (h == 0) return;
        try {
            JSONObject j = new JSONObject();
            StringBuilder sum = new StringBuilder();
            try {
                WifiManager wm = c.getSystemService(WifiManager.class);
                WifiInfo wi = wm == null ? null : wm.getConnectionInfo();
                if (wi != null) {
                    String ssid = wi.getSSID();
                    if (ssid != null && ssid.startsWith("\"") && ssid.endsWith("\"") && ssid.length() > 2) ssid = ssid.substring(1, ssid.length() - 1);
                    if (ssid != null && !ssid.isEmpty() && !ssid.contains("unknown ssid")) {
                        j.put("ssid", ssid);
                        sum.append("WLAN „").append(ssid).append("“");
                    }
                    String b = wi.getBSSID();
                    if (b != null && !b.equals("02:00:00:00:00:00") && j.has("ssid")) j.put("bssid", b);
                }
                // WLAN-Netze in der Naehe (staerkste zuerst): damit ortet der Server ueber Google/WiGLE auch
                // ohne GPS – z. B. in Gebaeuden. Nur Kennung (BSSID) und Signalstaerke, keine Namen.
                List<ScanResult> sr = wm == null ? null : wm.getScanResults();
                if (sr != null && !sr.isEmpty()) {
                    java.util.List<ScanResult> l = new java.util.ArrayList<>(sr);
                    l.sort((x, y) -> Integer.compare(y.level, x.level));
                    JSONArray aps = new JSONArray();
                    for (ScanResult r : l) {
                        if (aps.length() >= 12) break;
                        if (r.BSSID == null || r.BSSID.equals("02:00:00:00:00:00")) continue;
                        aps.put(new JSONObject().put("b", r.BSSID).put("s", r.level));
                    }
                    if (aps.length() > 0) j.put("aps", aps);
                }
            } catch (Exception ignored) {
            }
            if (loc != null) {
                j.put("lat", loc.getLatitude());
                j.put("lon", loc.getLongitude());
                if (loc.hasAccuracy()) j.put("acc", Math.round(loc.getAccuracy() * 10) / 10.0);
                j.put("t", loc.getTime() / 1000);
                if (src != null) j.put("src", src);
                else if (loc.getProvider() != null) j.put("src", loc.getProvider());
                if (sum.length() > 0) sum.append(" · ");
                sum.append("Standort").append(loc.hasAccuracy() ? " ±" + Math.round(loc.getAccuracy()) + " m" : "");
            }
            if (j.length() == 0) return;
            Native.report(h, j.toString());
            KroneVpnService.prefs(c).edit().putString("loc_last", sum.toString()).putBoolean("loc_sent_off", false).apply();
        } catch (Exception ignored) {
        }
    }
}
