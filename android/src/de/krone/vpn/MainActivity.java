package de.krone.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Locale;

/** Hauptbildschirm: Verbindungscode, Verbinden/Trennen, Live-Werte. Aufbau komplett im Code (keine Layout-Dateien). */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean dark;
    private int cBg, cCard, cInk, cMute, cAcc, cOk, cWarn, cBad, cSoft;
    private TextView tState, tSub, tDown, tUp, tPing, tTotal, tInfo, tErr, tName, tTitle, tUpd;
    private Button bUpd, bProfiles, bLoc, bCipher, bPin;
    /** eigenes Logo des Servers im Kopf (statt der Krone) */
    private android.widget.ImageView iLogo;
    private String shownLogo = null;
    private TextView tLoc;
    private static final int REQ_LOC = 3, REQ_LOC_BG = 4;
    private PowerButton power;
    private long lastRx = -1, lastTx = -1;
    /** Zeitpunkt des Trennens (Knopf zeigt kurz "wird getrennt") */
    private long stopAt = 0;
    private final java.util.List<View> cards = new java.util.ArrayList<>();

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
        Absturz.install(this);
        dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        cBg = dark ? 0xFF0F1115 : 0xFFF4F5F8;
        cCard = dark ? 0xFF171A21 : 0xFFFFFFFF;
        cInk = dark ? 0xFFE8EAF0 : 0xFF16181D;
        cMute = dark ? 0xFF9AA3B2 : 0xFF5D6472;
        cAcc = dark ? 0xFF6F95FF : 0xFF3B6CF6;
        cOk = dark ? 0xFF36C27A : 0xFF18A058;
        cWarn = dark ? 0xFFF0A72A : 0xFFB26A00;
        cBad = dark ? 0xFFFF5C7A : 0xFFD03050;
        cSoft = dark ? 0xFF1E222B : 0xFFEEF1F6;
        getWindow().setStatusBarColor(cBg);
        getWindow().setNavigationBarColor(cBg);
        if (!dark) getWindow().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR);
        build();
        // erster Start (bzw. erstes Mal mit 1.1.0): alle Erlaubnisse auf einer Seite erklaert und nacheinander abfragen
        if (!KroneVpnService.prefs(this).getBoolean("setup_done", false)) {
            ui.postDelayed(this::showSetup, 500);
            handleIntent(getIntent());
            return;
        }
        // spaeter: fehlende Erlaubnisse einmal gesammelt anfordern (Android zeigt seine eigene Abfrage)
        java.util.List<String> want = new java.util.ArrayList<>();
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            want.add("android.permission.POST_NOTIFICATIONS");
        }
        if (Standort.enabled(this) && !Standort.permitted(this) && !KroneVpnService.prefs(this).getBoolean("loc_asked", false)) {
            KroneVpnService.prefs(this).edit().putBoolean("loc_asked", true).apply();
            want.add(android.Manifest.permission.ACCESS_FINE_LOCATION);
            want.add(android.Manifest.permission.ACCESS_COARSE_LOCATION);
        }
        if (!want.isEmpty()) requestPermissions(want.toArray(new String[0]), REQ_LOC);
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        handleIntent(i);
    }

    /** kronevpn://v1/... aus einem gescannten QR-Code oder Link */
    private void handleIntent(Intent i) {
        // Benachrichtigung "Update bereit" angetippt -> Rueckfrage von Android oeffnen
        if (i != null && Updater.ACTION_INSTALL.equals(i.getAction())) {
            ui.post(this::installUpdate);
            return;
        }
        if (i == null || i.getData() == null) return;
        String code = i.getData().toString();
        if (code.startsWith("kronevpn://")) importCode(code);
    }

    private int dp(float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics());
    }

    private GradientDrawable round(int color, float r) {
        GradientDrawable g = new GradientDrawable();
        g.setColor(color);
        g.setCornerRadius(dp(r));
        return g;
    }

    private TextView text(String s, float sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setBackground(round(cCard, 18));
        c.setPadding(dp(18), dp(16), dp(18), dp(16));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(14);
        c.setLayoutParams(lp);
        // ein-/ausblendende Hinweise (Update, Fehler) gleiten weich statt zu springen
        android.animation.LayoutTransition lt = new android.animation.LayoutTransition();
        lt.enableTransitionType(android.animation.LayoutTransition.CHANGING);
        c.setLayoutTransition(lt);
        cards.add(c);
        return c;
    }

    private TextView stat(LinearLayout row, String label) {
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setBackground(round(cSoft, 12));
        box.setPadding(dp(10), dp(8), dp(10), dp(8));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1);
        lp.setMargins(dp(3), dp(3), dp(3), dp(3));
        box.setLayoutParams(lp);
        box.addView(text(label, 12, cMute, false));
        TextView v = text("–", 16, cInk, true);
        v.setSingleLine(true);
        box.addView(v);
        row.addView(box);
        return v;
    }

    private Button button(String s, boolean primary) {
        Button b = new Button(this);
        b.setText(s);
        b.setAllCaps(false);
        b.setTextSize(15);
        b.setTextColor(primary ? Color.WHITE : cInk);
        b.setBackground(round(primary ? cAcc : cSoft, 14));
        b.setPadding(dp(16), dp(12), dp(16), dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        b.setLayoutParams(lp);
        return b;
    }

    private void build() {
        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(cBg);
        sv.setFitsSystemWindows(true);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(dp(18), dp(22), dp(18), dp(30));
        sv.addView(root);

        tTitle = text("🛡️ KroneVPN", 28, cInk, true);
        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        head.setGravity(Gravity.CENTER_VERTICAL);
        iLogo = new android.widget.ImageView(this);
        iLogo.setScaleType(android.widget.ImageView.ScaleType.FIT_CENTER);
        LinearLayout.LayoutParams il = new LinearLayout.LayoutParams(dp(40), dp(40));
        il.rightMargin = dp(10);
        iLogo.setVisibility(View.GONE);
        head.addView(iLogo, il);
        head.addView(tTitle, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(head);
        tName = text("", 14, cMute, false);
        tName.setOnClickListener(v -> showProfiles());
        root.addView(tName);

        // Status + grosser Ein/Aus-Knopf (wie in der PC-App)
        LinearLayout c1 = card();
        c1.setGravity(Gravity.CENTER_HORIZONTAL);
        power = new PowerButton(this);
        power.setColors(cCard, dark ? 0xFF262B35 : 0xFFE2E6EE, cMute, cAcc, cOk, cWarn, dark);
        power.setOnClickListener(v -> toggle());
        LinearLayout.LayoutParams pl = new LinearLayout.LayoutParams(dp(172), dp(172));
        pl.topMargin = dp(2);
        c1.addView(power, pl);
        tState = text("Nicht verbunden", 24, cInk, true);
        tState.setGravity(Gravity.CENTER);
        tState.setPadding(0, dp(4), 0, 0);
        c1.addView(tState);
        tSub = text("", 14, cMute, false);
        tSub.setGravity(Gravity.CENTER);
        tSub.setPadding(0, dp(4), 0, dp(2));
        c1.addView(tSub);
        tUpd = text("", 13, cAcc, false);
        tUpd.setPadding(0, dp(10), 0, 0);
        tUpd.setVisibility(View.GONE);
        c1.addView(tUpd);
        bUpd = button("Update installieren", false);
        bUpd.setVisibility(View.GONE);
        bUpd.setOnClickListener(v -> installUpdate());
        c1.addView(bUpd);
        root.addView(c1);

        // Live-Werte
        LinearLayout c2 = card();
        LinearLayout r1 = new LinearLayout(this);
        tDown = stat(r1, "Download");
        tUp = stat(r1, "Upload");
        c2.addView(r1);
        LinearLayout r2 = new LinearLayout(this);
        tPing = stat(r2, "Ping");
        tTotal = stat(r2, "Gesamt");
        c2.addView(r2);
        tInfo = text("", 13, cMute, false);
        tInfo.setPadding(dp(3), dp(10), dp(3), 0);
        c2.addView(tInfo);
        tErr = text("", 13, cBad, false);
        tErr.setPadding(dp(3), dp(6), dp(3), 0);
        c2.addView(tErr);
        root.addView(c2);

        // Einstellungen
        LinearLayout c3 = card();
        c3.addView(text("Einrichtung", 16, cInk, true));
        bProfiles = button("Profile …", false);
        bProfiles.setOnClickListener(v -> showProfiles());
        c3.addView(bProfiles);
        Button paste = button("Profil hinzufügen (Code einfügen)", false);
        paste.setOnClickListener(v -> askCode());
        c3.addView(paste);
        bCipher = button("", false);
        bCipher.setOnClickListener(v -> chooseCipher());
        c3.addView(bCipher);
        showCipher();
        // Verknuepfung mit dem eigenen Logo (das Symbol der App selbst kann Android nicht austauschen)
        bPin = button("📌 Logo als Symbol auf den Startbildschirm", false);
        bPin.setVisibility(View.GONE);
        bPin.setOnClickListener(v -> {
            String t = getTitle() == null ? "KroneVPN" : getTitle().toString();
            if (!Logo.pin(this, t)) Toast.makeText(this, "Dein Startbildschirm erlaubt keine Verknüpfungen", Toast.LENGTH_LONG).show();
        });
        c3.addView(bPin);
        Button always = button("Immer verbunden (Always-on VPN) …", false);
        always.setOnClickListener(v -> {
            try {
                startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
                Toast.makeText(this, "Bei KroneVPN auf ⚙ tippen und „Durchgehend aktives VPN“ einschalten", Toast.LENGTH_LONG).show();
            } catch (Exception e) {
                Toast.makeText(this, "VPN-Einstellungen nicht gefunden", Toast.LENGTH_SHORT).show();
            }
        });
        c3.addView(always);
        bLoc = button("", false);
        bLoc.setOnClickListener(v -> toggleLocation());
        c3.addView(bLoc);
        tLoc = text("", 12.5f, cMute, false);
        tLoc.setPadding(dp(3), dp(4), dp(3), 0);
        c3.addView(tLoc);
        showLocation();
        Button stats = button("Statistik im Browser öffnen", false);
        stats.setOnClickListener(v -> openStats());
        c3.addView(stats);
        Button admin = button("Admin-Seite öffnen (im VPN)", false);
        admin.setOnClickListener(v -> openAdmin());
        c3.addView(admin);
        TextView help = text("Den Code erzeugt der Server mit  kvpn-server add \"Name\". Am einfachsten den QR-Code mit der Kamera scannen – die App öffnet sich dann von selbst.\n\n"
                + "KroneVPN läuft über HTTPS (Port 443) und kommt dadurch auch durch strenge Firmen-Firewalls (z. B. Sophos). "
                + "Alle Daten sind zusätzlich Ende-zu-Ende verschlüsselt (Noise + AES-256/ChaCha20) – auch wenn die Firewall HTTPS aufbricht.", 13, cMute, false);
        help.setPadding(dp(3), dp(12), dp(3), 0);
        c3.addView(help);
        root.addView(c3);

        TextView ver = text("Version " + Native.version(), 12, cMute, false);
        ver.setPadding(dp(3), dp(14), 0, 0);
        root.addView(ver);
        setContentView(sv);
        // Karten gleiten nacheinander herein
        for (int i = 0; i < cards.size(); i++) {
            View v = cards.get(i);
            v.setAlpha(0f);
            v.setTranslationY(dp(22));
            v.animate().alpha(1f).translationY(0).setStartDelay(60L * i).setDuration(420)
                    .setInterpolator(new android.view.animation.DecelerateInterpolator(1.6f)).start();
        }
    }

    /** Text weich wechseln (kurz ausblenden, neuer Text, einblenden) */
    private void swapText(TextView t, String s, int color) {
        if (s.contentEquals(t.getText()) && t.getCurrentTextColor() == color) return;
        if (t.getText().length() == 0 || t.getAlpha() < 1f) {
            t.setText(s);
            t.setTextColor(color);
            return;
        }
        t.animate().alpha(0f).setDuration(110).withEndAction(() -> {
            t.setText(s);
            t.setTextColor(color);
            t.animate().alpha(1f).setDuration(180).start();
        }).start();
    }

    // ------------------------------------------------------------------ Standort teilen (freiwillig)

    private void showLocation() {
        if (bLoc == null) return;
        bLoc.setText(Standort.enabled(this) ? "📍 Standort teilen: AN" : "📍 Standort teilen: aus");
        tLoc.setText(Standort.summary(this));
    }

    /** laufendes VPN: Benachrichtigung ("Standort wird geteilt") auf den neuen Stand bringen */
    private void refreshOngoing() {
        if (KroneVpnService.handle != 0) {
            try {
                startService(new Intent(this, KroneVpnService.class));
            } catch (Exception ignored) {
            }
        }
    }

    private void toggleLocation() {
        ui.postDelayed(this::refreshOngoing, 300);
        if (Standort.enabled(this)) {
            Standort.set(this, false);
            showLocation();
            Toast.makeText(this, "Standort wird nicht mehr geteilt – der Server löscht den gespeicherten Stand", Toast.LENGTH_LONG).show();
            return;
        }
        Standort.set(this, true);
        if (Standort.permitted(this)) askBackgroundLocation();
        else requestPermissions(new String[]{android.Manifest.permission.ACCESS_FINE_LOCATION, android.Manifest.permission.ACCESS_COARSE_LOCATION}, REQ_LOC);
        showLocation();
    }

    /** damit auch bei geschlossener App gemeldet wird: Android fragt nach "Immer zulassen" (eigene Einstellungsseite) */
    private void askBackgroundLocation() {
        if (android.os.Build.VERSION.SDK_INT < 29) return;
        if (checkSelfPermission(android.Manifest.permission.ACCESS_BACKGROUND_LOCATION) == android.content.pm.PackageManager.PERMISSION_GRANTED) return;
        if (KroneVpnService.prefs(this).getBoolean("loc_bg_asked", false)) return;
        KroneVpnService.prefs(this).edit().putBoolean("loc_bg_asked", true).apply();
        if (android.os.Build.VERSION.SDK_INT >= 30)
            Toast.makeText(this, "Für den Standort auch bei geschlossener App: „Immer zulassen“ wählen", Toast.LENGTH_LONG).show();
        requestPermissions(new String[]{android.Manifest.permission.ACCESS_BACKGROUND_LOCATION}, REQ_LOC_BG);
    }

    @Override
    public void onRequestPermissionsResult(int req, String[] perms, int[] res) {
        super.onRequestPermissionsResult(req, perms, res);
        if (req == REQ_SETUP || req == REQ_SETUP_BG) {
            showLocation();
            setupNext();
            return;
        }
        if (req == REQ_LOC) {
            if (Standort.enabled(this) && Standort.permitted(this)) {
                Standort.report(this);
                askBackgroundLocation();
            }
            showLocation();
        } else if (req == REQ_LOC_BG) {
            Standort.report(this);
            showLocation();
        }
    }

    private String code() {
        return KroneVpnService.prefs(this).getString("code", null);
    }

    // ------------------------------------------------------------------ Einrichtung beim ersten Start

    private static final int REQ_SETUP = 5, REQ_SETUP_BG = 6, REQ_VPN_SETUP = 7;
    private int setupStep = -1;
    private boolean setupWaitInstall;

    private LinearLayout setupRow(String icon, String title, String text) {
        LinearLayout r = new LinearLayout(this);
        r.setPadding(0, dp(8), 0, dp(8));
        TextView i = text(icon, 22, cInk, false);
        i.setPadding(0, 0, dp(12), 0);
        r.addView(i);
        LinearLayout t = new LinearLayout(this);
        t.setOrientation(LinearLayout.VERTICAL);
        t.addView(text(title, 15.5f, cInk, true));
        t.addView(text(text, 13.5f, cMute, false));
        r.addView(t, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        return r;
    }

    /** Alle Erlaubnisse auf einen Blick: wozu sie da sind. Ein Knopf fragt dann alles nacheinander ab. */
    private void showSetup() {
        if (isFinishing()) return;
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(22), dp(6), dp(22), dp(4));
        box.addView(text("KroneVPN braucht dafür ein paar Erlaubnisse von Android. Alles bleibt zwischen diesem Gerät und deinem eigenen Server.", 14, cMute, false));
        box.addView(setupRow("🔒", "VPN-Verbindung", "Damit der Datenverkehr verschlüsselt über deinen Server läuft."));
        box.addView(setupRow("🔔", "Benachrichtigungen", "Zeigt, dass das VPN läuft und ob der Standort geteilt wird, und meldet Updates."));
        box.addView(setupRow("📍", "Standort – auch im Hintergrund", "WLAN-Name und Standort gehen nur an deinen Server: Admin-Seite, Bewegungs-Karte und Orten, falls das Handy verloren geht oder gestohlen wird. Jederzeit in der App abschaltbar."));
        box.addView(setupRow("📦", "Updates installieren", "Damit sich KroneVPN selbst aktualisieren kann – nur geprüfte, signierte Versionen von deinem Server."));
        ScrollView sv = new ScrollView(this);
        sv.addView(box);
        new AlertDialog.Builder(this)
                .setTitle("Einrichtung")
                .setView(sv)
                .setCancelable(false)
                .setPositiveButton("Alles einrichten", (d, w) -> {
                    setupStep = -1;
                    setupNext();
                })
                .setNegativeButton("Später", (d, w) -> KroneVpnService.prefs(this).edit().putBoolean("setup_done", true).apply())
                .show();
    }

    private boolean granted(String p) {
        return checkSelfPermission(p) == android.content.pm.PackageManager.PERMISSION_GRANTED;
    }

    /** naechste Abfrage der Einrichtung (VPN -> Hinweise + Standort -> Standort im Hintergrund -> Updates) */
    private void setupNext() {
        setupStep++;
        switch (setupStep) {
            case 0: {
                Intent prep = VpnService.prepare(this);
                if (prep != null) {
                    startActivityForResult(prep, REQ_VPN_SETUP);
                    return;
                }
                setupNext();
                return;
            }
            case 1: {
                java.util.List<String> want = new java.util.ArrayList<>();
                if (android.os.Build.VERSION.SDK_INT >= 33 && !granted("android.permission.POST_NOTIFICATIONS")) want.add("android.permission.POST_NOTIFICATIONS");
                if (Standort.enabled(this) && !granted(android.Manifest.permission.ACCESS_FINE_LOCATION)) {
                    want.add(android.Manifest.permission.ACCESS_FINE_LOCATION);
                    want.add(android.Manifest.permission.ACCESS_COARSE_LOCATION);
                }
                KroneVpnService.prefs(this).edit().putBoolean("loc_asked", true).apply();
                if (!want.isEmpty()) {
                    requestPermissions(want.toArray(new String[0]), REQ_SETUP);
                    return;
                }
                setupNext();
                return;
            }
            case 2: {
                KroneVpnService.prefs(this).edit().putBoolean("loc_bg_asked", true).apply();
                if (android.os.Build.VERSION.SDK_INT >= 29 && Standort.enabled(this) && Standort.permitted(this)
                        && !granted(android.Manifest.permission.ACCESS_BACKGROUND_LOCATION)) {
                    if (android.os.Build.VERSION.SDK_INT >= 30)
                        Toast.makeText(this, "Für den Standort auch bei geschlossener App: „Immer zulassen“ wählen", Toast.LENGTH_LONG).show();
                    requestPermissions(new String[]{android.Manifest.permission.ACCESS_BACKGROUND_LOCATION}, REQ_SETUP_BG);
                    return;
                }
                setupNext();
                return;
            }
            case 3: {
                if (!getPackageManager().canRequestPackageInstalls()) {
                    try {
                        Toast.makeText(this, "Bei KroneVPN „Aus dieser Quelle zulassen“ einschalten, dann zurück", Toast.LENGTH_LONG).show();
                        startActivity(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + getPackageName())));
                        setupWaitInstall = true;
                        return;
                    } catch (Exception ignored) {
                    }
                }
                setupNext();
                return;
            }
            default:
                setupStep = -1;
                KroneVpnService.prefs(this).edit().putBoolean("setup_done", true).apply();
                Standort.report(this);
                showLocation();
                Toast.makeText(this, code() == null ? "Fertig! Jetzt den Verbindungscode einfügen." : "Fertig eingerichtet – zum Verbinden auf den Knopf tippen.", Toast.LENGTH_LONG).show();
                if (code() == null) askCode();
                refresh();
        }
    }

    // ------------------------------------------------------------------ Profile
    // Mehrere Verbindungscodes (z. B. verschiedene Server) in prefs "profiles" (JSON-Liste); "code" = aktives Profil.

    /** gleiches Profil = gleicher Server + gleicher Geraetename */
    private static String key(JSONObject p) {
        return p.optString("url") + "|" + p.optString("name");
    }

    private static JSONObject parse(String code) {
        try {
            JSONObject j = new JSONObject(Native.parse(code));
            return j.has("error") ? null : j;
        } catch (Exception e) {
            return null;
        }
    }

    /** gespeicherte Profile (geparst); das aktive ist immer dabei */
    private java.util.List<JSONObject> profiles() {
        java.util.List<JSONObject> l = new java.util.ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        try {
            JSONArray a = new JSONArray(KroneVpnService.prefs(this).getString("profiles", "[]"));
            for (int i = 0; i < a.length(); i++) {
                JSONObject p = parse(a.getString(i));
                if (p != null && seen.add(key(p))) l.add(p);
            }
        } catch (Exception ignored) {
        }
        String c = code();
        JSONObject cur = c == null ? null : parse(c);
        if (cur != null && !seen.contains(key(cur))) {
            l.add(cur);
            saveProfiles(l);
        }
        return l;
    }

    private void saveProfiles(java.util.List<JSONObject> l) {
        JSONArray a = new JSONArray();
        for (JSONObject p : l) a.put(p.optString("code"));
        KroneVpnService.prefs(this).edit().putString("profiles", a.toString()).apply();
    }

    /** Profil aktiv machen; lief das VPN, wird mit dem neuen Profil neu verbunden */
    private void useProfile(JSONObject p) {
        boolean wasOn = KroneVpnService.handle != 0;
        KroneVpnService.prefs(this).edit().putString("code", p.optString("code")).apply();
        Toast.makeText(this, "Profil: " + p.optString("title", "KroneVPN") + " – " + p.optString("name"), Toast.LENGTH_SHORT).show();
        if (wasOn) {
            startService(new Intent(this, KroneVpnService.class).setAction(KroneVpnService.ACTION_STOP));
            ui.postDelayed(this::connect, 800);
        }
        lastRx = lastTx = -1;
        refresh();
    }

    private void showProfiles() {
        java.util.List<JSONObject> l = profiles();
        JSONObject cur = code() == null ? null : parse(code());
        String curKey = cur == null ? "" : key(cur);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(4));
        final AlertDialog[] dlg = new AlertDialog[1];
        if (l.isEmpty()) box.addView(text("Noch keine Profile – füge einen Verbindungscode hinzu.", 14, cMute, false));
        for (JSONObject p : l) {
            boolean active = key(p).equals(curKey);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            GradientDrawable bg = round(active ? (dark ? 0xFF15221C : 0xFFE6F6EE) : cSoft, 14);
            if (active) bg.setStroke(dp(1), cOk);
            row.setBackground(bg);
            row.setPadding(dp(14), dp(10), dp(14), dp(10));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.topMargin = dp(8);
            row.setLayoutParams(lp);
            row.addView(text(p.optString("title", "KroneVPN") + (active ? "   ● aktiv" : ""), 16, active ? cOk : cInk, true));
            String host = p.optString("url").replaceFirst("^wss?://", "").split("/")[0];
            row.addView(text("„" + p.optString("name") + "“ · " + host, 13, cMute, false));
            row.setOnClickListener(v -> {
                if (dlg[0] != null) dlg[0].dismiss();
                if (!active) useProfile(p);
            });
            row.setOnLongClickListener(v -> {
                if (active) {
                    Toast.makeText(this, "Das aktive Profil kann nicht entfernt werden – erst ein anderes wählen", Toast.LENGTH_LONG).show();
                    return true;
                }
                new AlertDialog.Builder(this)
                        .setTitle("Profil entfernen?")
                        .setMessage(p.optString("title", "KroneVPN") + " – " + p.optString("name"))
                        .setPositiveButton("Entfernen", (d, w) -> {
                            java.util.List<JSONObject> n = profiles();
                            n.removeIf(x -> key(x).equals(key(p)));
                            saveProfiles(n);
                            if (dlg[0] != null) dlg[0].dismiss();
                            showProfiles();
                        })
                        .setNegativeButton("Abbrechen", null)
                        .show();
                return true;
            });
            box.addView(row);
        }
        TextView hint = text("Antippen = verwenden · lange drücken = entfernen", 12, cMute, false);
        hint.setPadding(dp(2), dp(10), 0, 0);
        box.addView(hint);
        ScrollView sv = new ScrollView(this);
        sv.addView(box);
        dlg[0] = new AlertDialog.Builder(this)
                .setTitle("Profile")
                .setView(sv)
                .setPositiveButton("Hinzufügen", (d, w) -> askCode())
                .setNegativeButton("Schließen", null)
                .show();
    }

    private void askCode() {
        final EditText in = new EditText(this);
        in.setHint("kronevpn://v1/…");
        in.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        in.setMinLines(3);
        ClipboardManager cb = getSystemService(ClipboardManager.class);
        try {
            ClipData d = cb.getPrimaryClip();
            if (d != null && d.getItemCount() > 0) {
                CharSequence t = d.getItemAt(0).coerceToText(this);
                if (t != null && t.toString().trim().startsWith("kronevpn://")) in.setText(t.toString().trim());
            }
        } catch (Exception ignored) {
        }
        new AlertDialog.Builder(this)
                .setTitle("Verbindungscode")
                .setView(in)
                .setPositiveButton("Speichern", (d, w) -> importCode(in.getText().toString()))
                .setNegativeButton("Abbrechen", null)
                .show();
    }

    // ------------------------------------------------------------------ Verschluesselung (Auto / AES-256 / ChaCha20)

    static final String[] CIPHERS = {"auto", "aes", "chacha"};

    static String cipherPref(android.content.Context c) {
        return KroneVpnService.prefs(c).getString("cipher", "auto");
    }

    private String cipherName(String c) {
        switch (c) {
            case "aes": return "AES-256-GCM";
            case "chacha": return "ChaCha20-Poly1305";
            default: return "Auto (" + (Native.aesHw() ? "AES-256-GCM" : "ChaCha20") + ")";
        }
    }

    private void showCipher() {
        if (bCipher != null) bCipher.setText("🔒 Sicherheit · " + cipherName(cipherPref(this)));
    }

    /** Sicherheit: was man waehlen kann (Verfahren) und was immer an ist – gleiche Texte wie in der PC-App */
    private void chooseCipher() {
        boolean hw = Native.aesHw();
        String cur = cipherPref(this);
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(22), dp(8), dp(22), dp(4));
        ScrollView sc = new ScrollView(this);
        sc.addView(box);

        box.addView(text("Deine Daten sind immer verschlüsselt – ausschalten kann man das nicht. Hier wählst du nur das Verfahren. "
                + "Alle drei Möglichkeiten sind gleich sicher (geprüfte Standards, 256-Bit-Schlüssel); sie unterscheiden sich nur in Tempo und Akku.", 14, cMute, false));
        TextView h1 = text("Verschlüsselung wählen", 15.5f, cInk, true);
        h1.setPadding(0, dp(14), 0, dp(6));
        box.addView(h1);

        String[][] opt = {
                {"auto", "Auto (empfohlen)", hw
                        ? "Die App nimmt automatisch das schnellste Verfahren für dieses Gerät – hier AES-256-GCM, weil der Prozessor AES-Befehle hat. Passt fast immer."
                        : "Die App nimmt automatisch das schnellste Verfahren für dieses Gerät – hier ChaCha20, weil der Prozessor keine AES-Befehle hat. Passt fast immer."},
                {"aes", "AES-256-GCM", hw
                        ? "Weltweiter Standard (Banken, Behörden, HTTPS). Auf diesem Handy sehr schnell, weil der Prozessor AES direkt beherrscht."
                        : "Weltweiter Standard (Banken, Behörden, HTTPS). Auf diesem Handy langsamer und braucht mehr Akku, weil dem Prozessor die AES-Befehle fehlen."},
                {"chacha", "ChaCha20-Poly1305", "Moderner Standard (auch in WireGuard). Auf jedem Gerät schnell, auch auf älteren ohne AES-Befehle."},
        };
        final AlertDialog[] dlg = new AlertDialog[1];
        for (String[] o : opt) {
            boolean an = o[0].equals(cur);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.VERTICAL);
            GradientDrawable bg = round(an ? (cAcc & 0x00FFFFFF) | 0x26000000 : cSoft, 14);
            if (an) bg.setStroke(dp(1.5f), cAcc);
            row.setBackground(bg);
            row.setPadding(dp(14), dp(10), dp(14), dp(11));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.bottomMargin = dp(8);
            row.setLayoutParams(lp);
            row.addView(text((an ? "◉  " : "○  ") + o[1], 15.5f, an ? cAcc : cInk, true));
            TextView d = text(o[2], 13, cMute, false);
            d.setPadding(0, dp(2), 0, 0);
            row.addView(d);
            row.setClickable(true);
            row.setFocusable(true);
            String c = o[0];
            row.setOnClickListener(v -> {
                if (dlg[0] != null) dlg[0].dismiss();
                if (c.equals(cipherPref(this))) return;
                KroneVpnService.prefs(this).edit().putString("cipher", c).apply();
                Native.cipher(c);
                showCipher();
                if (KroneVpnService.handle != 0) {
                    Native.reconnect(KroneVpnService.handle);
                    Toast.makeText(this, cipherName(c) + " – verbinde kurz neu …", Toast.LENGTH_SHORT).show();
                }
            });
            box.addView(row);
        }
        String aktiv = "";
        try {
            if (KroneVpnService.handle != 0) aktiv = new JSONObject(Native.status(KroneVpnService.handle)).optString("cipher", "");
        } catch (Exception ignored) {
        }
        TextView st = text(aktiv.isEmpty() ? "Gilt ab der nächsten Verbindung." : "Jetzt aktiv: " + aktiv + ". Ein Wechsel verbindet das VPN kurz neu (1–2 s).",
                13, aktiv.isEmpty() ? cMute : cOk, false);
        st.setPadding(0, dp(2), 0, dp(2));
        box.addView(st);
        box.addView(text("Wann umstellen? Eigentlich nie – nur zum Ausprobieren, falls die Verbindung langsam ist oder der Akku schnell leer wird.", 13, cMute, false));

        TextView h2 = text("Immer aktiv (nicht abschaltbar)", 15.5f, cInk, true);
        h2.setPadding(0, dp(16), 0, dp(4));
        box.addView(h2);
        String[][] immer = {
                {"HTTPS-Hülle (TLS 1.3, Port 443)", "Für Firewalls wie Sophos sieht das VPN aus wie eine normale Webseite. Deshalb kommt es durch."},
                {"Geräte-Schlüssel (Noise)", "Nur dein Server und deine Geräte können die Daten lesen – auch wenn eine Firmen-Firewall HTTPS aufbricht und hineinschaut."},
                {"Tarnung", "Paketgrößen und Takt ändern sich bei jeder Verbindung, damit keine typischen VPN-Muster entstehen. "
                        + "Das ist keine Verschlüsselung, nur eine Verkleidung – die Sicherheit kommt von den beiden Punkten oben."},
        };
        for (String[] i : immer) {
            TextView t = text("✔  " + i[0], 14, cOk, true);
            t.setPadding(0, dp(6), 0, 0);
            box.addView(t);
            TextView d = text(i[1], 13, cMute, false);
            d.setPadding(dp(22), dp(1), 0, 0);
            box.addView(d);
        }

        dlg[0] = new AlertDialog.Builder(this)
                .setTitle("Sicherheit")
                .setView(sc)
                .setNegativeButton("Schließen", null)
                .show();
    }

    private void installUpdate() {
        if (Updater.showConfirm(this)) return;
        try {
            JSONObject j = new JSONObject(Native.status(KroneVpnService.handle));
            String f = j.optString("update_file", "");
            if (f.isEmpty()) {
                Toast.makeText(this, "Update wird noch geladen", Toast.LENGTH_SHORT).show();
                return;
            }
            Updater.installing = "";
            Updater.install(this, f, j.optString("update_version", ""), true);
        } catch (Exception ignored) {
        }
    }

    /** App im Vordergrund: liegt ein fertig geladenes Update bereit, die Rueckfrage von Android gleich zeigen */
    private void updateOnOpen() {
        try {
            long h = KroneVpnService.handle;
            if (h == 0) return;
            JSONObject j = new JSONObject(Native.status(h));
            Updater.onForeground(this, j.optString("update_file", ""), j.optString("update_version", ""));
        } catch (Exception ignored) {
        }
    }

    private void importCode(String code) {
        try {
            JSONObject c = new JSONObject(Native.parse(code));
            if (c.has("error")) {
                Toast.makeText(this, c.getString("error"), Toast.LENGTH_LONG).show();
                return;
            }
            boolean wasOn = KroneVpnService.handle != 0;
            // als Profil merken (gleiches Profil wird ersetzt) und aktiv machen
            java.util.List<JSONObject> l = profiles();
            boolean replaced = false;
            for (int i = 0; i < l.size(); i++) {
                if (key(l.get(i)).equals(key(c))) {
                    l.set(i, c);
                    replaced = true;
                }
            }
            if (!replaced) l.add(c);
            saveProfiles(l);
            KroneVpnService.prefs(this).edit().putString("code", c.getString("code")).apply();
            Toast.makeText(this, c.optString("title", "KroneVPN") + ": Profil „" + c.getString("name") + "“ gespeichert", Toast.LENGTH_SHORT).show();
            if (wasOn) {
                startService(new Intent(this, KroneVpnService.class).setAction(KroneVpnService.ACTION_STOP));
                ui.postDelayed(this::connect, 800);
            }
            refresh();
        } catch (Exception e) {
            Toast.makeText(this, "Das ist kein gültiger Verbindungscode – er beginnt mit kronevpn://v1/ und kommt vom Server (kvpn-server add).", Toast.LENGTH_LONG).show();
        }
    }

    private void toggle() {
        if (KroneVpnService.handle != 0) {
            stopAt = System.currentTimeMillis();
            power.setState(PowerButton.DISCONNECTING);
            startService(new Intent(this, KroneVpnService.class).setAction(KroneVpnService.ACTION_STOP));
            ui.postDelayed(this::refresh, 300);
        } else {
            connect();
        }
    }

    private void connect() {
        if (code() == null) {
            askCode();
            return;
        }
        Intent prep = VpnService.prepare(this);
        if (prep != null) startActivityForResult(prep, REQ_VPN);
        else onActivityResult(REQ_VPN, RESULT_OK, null);
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        if (req == REQ_VPN_SETUP) {
            setupNext();
            return;
        }
        if (req == REQ_VPN && res == RESULT_OK) {
            KroneVpnService.lastError = "";
            stopAt = 0;
            if (power != null) power.setState(PowerButton.CONNECTING);
            startService(new Intent(this, KroneVpnService.class));
        } else if (req == REQ_VPN) {
            Toast.makeText(this, "Ohne die VPN-Erlaubnis von Android geht es nicht. Nochmal auf den Knopf tippen und „OK“ wählen. (Läuft ein anderes VPN? Dann dort ausschalten.)", Toast.LENGTH_LONG).show();
        }
    }

    private void openStats() {
        try {
            String url = new JSONObject(Native.parse(code() == null ? "" : code())).optString("url", "");
            String host = url.replaceFirst("^wss?://", "").split("/")[0];
            if (host.isEmpty()) {
                Toast.makeText(this, "Zuerst den Verbindungscode einfügen", Toast.LENGTH_SHORT).show();
                return;
            }
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("https://" + host + "/stats")));
        } catch (Exception e) {
            Toast.makeText(this, "Kein Browser gefunden – bitte einen Browser installieren", Toast.LENGTH_SHORT).show();
        }
    }

    /** Admin-Seite des Servers im Tunnel: http://<Netz>.1:8180 (nur wenn verbunden, Passwort beim ersten Mal festlegen) */
    private void openAdmin() {
        if (KroneVpnService.handle == 0) {
            Toast.makeText(this, "Zuerst verbinden – die Admin-Seite gibt es nur im VPN", Toast.LENGTH_LONG).show();
            return;
        }
        try {
            String[] a = new JSONObject(Native.parse(code())).optString("ip4").split("/");
            int p = Integer.parseInt(a[1]);
            long ip = 0;
            for (String x : a[0].split("\\.")) ip = ip * 256 + Integer.parseInt(x);
            long net = p == 0 ? 0 : (ip & (0xFFFFFFFFL << (32 - p)) & 0xFFFFFFFFL);
            long srv = net + 1;
            String host = (srv >> 24 & 255) + "." + (srv >> 16 & 255) + "." + (srv >> 8 & 255) + "." + (srv & 255);
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse("http://" + host + ":8180/")));
        } catch (Exception e) {
            Toast.makeText(this, "Admin-Seite nicht zu öffnen", Toast.LENGTH_SHORT).show();
        }
    }

    private static String rate(double bytesPerSec) {
        double b = bytesPerSec * 8;
        if (b >= 1e9) return String.format(Locale.GERMANY, "%.2f Gbit/s", b / 1e9);
        if (b >= 1e6) return String.format(Locale.GERMANY, "%.1f Mbit/s", b / 1e6);
        return String.format(Locale.GERMANY, "%.0f kbit/s", b / 1e3);
    }

    private static String bytes(double b) {
        String[] u = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        while (b >= 1024 && i < u.length - 1) {
            b /= 1024;
            i++;
        }
        return i == 0 ? String.format(Locale.GERMANY, "%.0f B", b) : String.format(Locale.GERMANY, "%.1f %s", b, u[i]);
    }

    private void refresh() {
        String c = code();
        try {
            JSONObject pc = c == null ? null : new JSONObject(Native.parse(c));
            int n = profiles().size();
            tName.setText(pc == null ? "Noch kein Verbindungscode" : "Gerät: " + pc.optString("name") + (n > 1 ? "  ·  Profil wechseln ›" : ""));
            bProfiles.setText(n > 1 ? "Profile (" + n + ") …" : "Profile …");
            String t = pc == null ? "KroneVPN" : pc.optString("title", "KroneVPN");
            String lid = Logo.id(this);
            if (!lid.equals(shownLogo)) {
                shownLogo = lid;
                android.graphics.Bitmap b = Logo.bitmap(this);
                iLogo.setImageBitmap(b);
                iLogo.setVisibility(b != null ? View.VISIBLE : View.GONE);
                bPin.setVisibility(b != null && Logo.canPin(this) ? View.VISIBLE : View.GONE);
                if (b != null) iLogo.animate().alpha(1f).setDuration(300).start();
            }
            tTitle.setText(iLogo.getVisibility() == View.VISIBLE ? t : "🛡️ " + t);
            setTitle(t);
        } catch (Exception ignored) {
        }
        long h = KroneVpnService.handle;
        String state = "stopped";
        JSONObject j = null;
        try {
            j = new JSONObject(Native.status(h));
            state = j.optString("state", "stopped");
        } catch (Exception ignored) {
        }
        boolean stopping = System.currentTimeMillis() - stopAt < 1500;
        if (stopping) {
            swapText(tState, "Trenne …", cWarn);
            power.setState(PowerButton.DISCONNECTING);
        } else switch (state) {
            case "connected":
                swapText(tState, "Verbunden", cOk);
                power.setState(PowerButton.CONNECTED);
                break;
            case "connecting":
                swapText(tState, "Verbinde …", cAcc);
                power.setState(PowerButton.CONNECTING);
                break;
            case "waiting":
                swapText(tState, "Warte auf Netz …", cWarn);
                power.setState(PowerButton.CONNECTING);
                break;
            default:
                swapText(tState, "Nicht verbunden", cInk);
                power.setState(h != 0 ? PowerButton.CONNECTING : PowerButton.OFF);
        }

        String err = KroneVpnService.lastError;
        if (j != null && h != 0) {
            long rx = j.optLong("rx_bytes"), tx = j.optLong("tx_bytes");
            if (lastRx >= 0) {
                tDown.setText(rate(Math.max(0, rx - lastRx)));
                tUp.setText(rate(Math.max(0, tx - lastTx)));
            }
            lastRx = rx;
            lastTx = tx;
            double rtt = j.optDouble("rtt_ms", 0);
            tPing.setText(rtt > 0 ? String.format(Locale.GERMANY, "%.0f ms", rtt) : "–");
            tTotal.setText(bytes(rx + tx));
            long since = j.optLong("connected_since");
            tSub.setText("connected".equals(state) && since > 0
                    ? "seit " + duration(System.currentTimeMillis() / 1000 - since) + " · " + j.optString("server")
                    : "");
            StringBuilder info = new StringBuilder();
            if ("connected".equals(state)) {
                if (!j.optString("cipher").isEmpty()) info.append("🔒 ").append(j.optString("cipher")).append(" · Tarnung aktiv. ");
                if (j.optBoolean("via_proxy")) info.append("Über Proxy verbunden. ");
                if (!j.optString("tls_issuer").isEmpty()) {
                    if (j.optBoolean("tls_trusted")) info.append("TLS direkt (Zertifikat: ").append(j.optString("tls_issuer")).append(").");
                    else info.append("⚠ Das Netz bricht HTTPS auf (").append(j.optString("tls_issuer"))
                            .append(") – deine Daten bleiben trotzdem verschlüsselt.");
                }
            }
            tInfo.setText(info.toString());
            String le = j.optString("last_error");
            if (!"connected".equals(state) && !le.isEmpty()) err = le;
        } else {
            lastRx = lastTx = -1;
            tDown.setText("–");
            tUp.setText("–");
            tPing.setText("–");
            tTotal.setText("–");
            tSub.setText(c == null ? "Zuerst den Verbindungscode einfügen" : "Zum Verbinden auf den Knopf tippen");
            tInfo.setText("");
        }
        tErr.setText(err == null ? "" : err);

        // automatische Updates
        String um = Updater.message;
        JSONObject u = j == null ? null : j.optJSONObject("update");
        if (um.isEmpty() && u != null && !u.optString("version").isEmpty() && !u.optBoolean("done")) {
            long size = u.optLong("size"), got = u.optLong("got");
            um = "Neue Version " + u.optString("version") + " wird geladen … " + (size > 0 ? got * 100 / size : 0) + " %";
        }
        if (um.isEmpty() && u != null && !u.optString("error").isEmpty()) um = u.optString("error");
        tUpd.setText(um);
        tUpd.setVisibility(um.isEmpty() ? View.GONE : View.VISIBLE);
        boolean ready = j != null && !j.optString("update_file").isEmpty();
        bUpd.setVisibility(Updater.confirm != null || (ready && !Updater.failed.isEmpty()) ? View.VISIBLE : View.GONE);
    }

    private static String duration(long s) {
        if (s < 60) return s + " s";
        if (s < 3600) return (s / 60) + " min";
        return (s / 3600) + " h " + (s % 3600 / 60) + " min";
    }

    private final Runnable tick = new Runnable() {
        @Override
        public void run() {
            refresh();
            ui.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onResume() {
        super.onResume();
        if (setupWaitInstall) {
            setupWaitInstall = false;
            ui.postDelayed(this::setupNext, 300);
        }
        Updater.visible = this;
        ui.post(tick);
        Standort.report(this);
        ui.postDelayed(this::showLocation, 2500);
        ui.postDelayed(this::updateOnOpen, 1500);
    }

    @Override
    protected void onPause() {
        if (Updater.visible == this) Updater.visible = null;
        ui.removeCallbacks(tick);
        super.onPause();
    }
}
