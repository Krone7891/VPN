package de.krone.vpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.content.res.Configuration;
import android.graphics.Bitmap;
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
import android.widget.ImageView;
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
    private Button bMain, bUpd, bProfiles;
    private View dot;
    private long lastRx = -1, lastTx = -1;

    @Override
    protected void onCreate(Bundle s) {
        super.onCreate(s);
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
        // Android 13+: einmal fragen, ob die App Hinweise zeigen darf (z. B. "Update bereit")
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission("android.permission.POST_NOTIFICATIONS") != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 2);
        }
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
        TextView title = tTitle;
        root.addView(title);
        tName = text("", 14, cMute, false);
        tName.setOnClickListener(v -> showProfiles());
        root.addView(tName);

        // Status + grosser Knopf
        LinearLayout c1 = card();
        LinearLayout head = new LinearLayout(this);
        head.setGravity(Gravity.CENTER_VERTICAL);
        dot = new View(this);
        LinearLayout.LayoutParams dl = new LinearLayout.LayoutParams(dp(12), dp(12));
        dl.rightMargin = dp(10);
        dot.setLayoutParams(dl);
        dot.setBackground(round(cMute, 6));
        head.addView(dot);
        tState = text("Getrennt", 22, cInk, true);
        head.addView(tState);
        c1.addView(head);
        tSub = text("", 14, cMute, false);
        tSub.setPadding(0, dp(4), 0, 0);
        c1.addView(tSub);
        bMain = button("Verbinden", true);
        bMain.setOnClickListener(v -> toggle());
        c1.addView(bMain);
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
        Button show = button("Code anzeigen (QR-Code + Text)", false);
        show.setOnClickListener(v -> showCode());
        c3.addView(show);
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
        Button stats = button("Statistik im Browser öffnen", false);
        stats.setOnClickListener(v -> openStats());
        c3.addView(stats);
        Button admin = button("Admin-Seite öffnen (im VPN)", false);
        admin.setOnClickListener(v -> openAdmin());
        c3.addView(admin);
        TextView help = text("Den Code erzeugt der Server mit  kvpn-server add \"Name\". Am einfachsten den QR-Code mit der Kamera scannen – die App öffnet sich dann von selbst.\n\n"
                + "KroneVPN läuft über HTTPS (Port 443) und kommt dadurch auch durch strenge Firmen-Firewalls (z. B. Sophos). "
                + "Alle Daten sind zusätzlich Ende-zu-Ende verschlüsselt (Noise/ChaCha20) – auch wenn die Firewall HTTPS aufbricht.", 13, cMute, false);
        help.setPadding(dp(3), dp(12), dp(3), 0);
        c3.addView(help);
        root.addView(c3);

        TextView ver = text("Version " + Native.version(), 12, cMute, false);
        ver.setPadding(dp(3), dp(14), 0, 0);
        root.addView(ver);
        setContentView(sv);
    }

    private String code() {
        return KroneVpnService.prefs(this).getString("code", null);
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

    /** gespeicherten Code wieder anzeigen: als QR-Code (z. B. fuer ein zweites Geraet) und als Text */
    private void showCode() {
        String c = code();
        if (c == null) {
            Toast.makeText(this, "Noch kein Verbindungscode gespeichert", Toast.LENGTH_SHORT).show();
            return;
        }
        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(20), dp(12), dp(20), dp(4));
        Bitmap bm = qrBitmap(c);
        if (bm != null) {
            ImageView iv = new ImageView(this);
            iv.setImageBitmap(bm);
            iv.setAdjustViewBounds(true);
            box.addView(iv, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        }
        TextView t = text(c, 12, cInk, false);
        t.setTypeface(Typeface.MONOSPACE);
        t.setTextIsSelectable(true);
        t.setPadding(0, dp(10), 0, 0);
        box.addView(t);
        TextView warn = text("Geheim halten – wer den Code hat, kann sich als dieses Gerät verbinden. Auf dem Server merken: kvpn-server import '<code>'", 12, cMute, false);
        warn.setPadding(0, dp(8), 0, 0);
        box.addView(warn);
        ScrollView sv = new ScrollView(this);
        sv.addView(box);
        new AlertDialog.Builder(this)
                .setTitle("Verbindungscode")
                .setView(sv)
                .setPositiveButton("Kopieren", (d, w) -> {
                    getSystemService(ClipboardManager.class).setPrimaryClip(ClipData.newPlainText("Verbindungscode", c));
                    Toast.makeText(this, "Code kopiert", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("Schließen", null)
                .show();
    }

    private Bitmap qrBitmap(String s) {
        try {
            String[] rows = Native.qr(s).split("\n");
            int w = Integer.parseInt(rows[0].trim());
            int q = 4, scale = 10, size = (w + 2 * q) * scale;
            int[] px = new int[size * size];
            java.util.Arrays.fill(px, Color.WHITE);
            for (int y = 0; y < w; y++) {
                String r = rows[y + 1];
                for (int x = 0; x < w; x++) {
                    if (r.charAt(x) != '1') continue;
                    for (int dy = 0; dy < scale; dy++) {
                        int base = ((y + q) * scale + dy) * size + (x + q) * scale;
                        java.util.Arrays.fill(px, base, base + scale, Color.BLACK);
                    }
                }
            }
            return Bitmap.createBitmap(px, size, size, Bitmap.Config.ARGB_8888);
        } catch (Exception e) {
            return null;
        }
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
            Toast.makeText(this, "Code ungültig", Toast.LENGTH_LONG).show();
        }
    }

    private void toggle() {
        if (KroneVpnService.handle != 0) {
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
        if (req == REQ_VPN && res == RESULT_OK) {
            KroneVpnService.lastError = "";
            startService(new Intent(this, KroneVpnService.class));
        } else if (req == REQ_VPN) {
            Toast.makeText(this, "Ohne VPN-Berechtigung geht es nicht", Toast.LENGTH_LONG).show();
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
            Toast.makeText(this, "Kein Browser gefunden", Toast.LENGTH_SHORT).show();
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
            tTitle.setText("🛡️ " + t);
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
        int col;
        switch (state) {
            case "connected":
                tState.setText("Verbunden");
                col = cOk;
                break;
            case "connecting":
                tState.setText("Verbinde …");
                col = cWarn;
                break;
            case "waiting":
                tState.setText("Warte auf Netz …");
                col = cWarn;
                break;
            default:
                tState.setText("Getrennt");
                col = cMute;
        }
        dot.setBackground(round(col, 6));
        bMain.setText(h != 0 ? "Trennen" : "Verbinden");
        bMain.setBackground(round(h != 0 ? cSoft : cAcc, 14));
        bMain.setTextColor(h != 0 ? cInk : Color.WHITE);

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
            tSub.setText(c == null ? "Zuerst den Verbindungscode einfügen" : "Tippe auf Verbinden");
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
        Updater.visible = this;
        ui.post(tick);
        ui.postDelayed(this::updateOnOpen, 1500);
    }

    @Override
    protected void onPause() {
        if (Updater.visible == this) Updater.visible = null;
        ui.removeCallbacks(tick);
        super.onPause();
    }
}
