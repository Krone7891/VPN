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

import org.json.JSONObject;

import java.util.Locale;

/** Hauptbildschirm: Verbindungscode, Verbinden/Trennen, Live-Werte. Aufbau komplett im Code (keine Layout-Dateien). */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 1;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean dark;
    private int cBg, cCard, cInk, cMute, cAcc, cOk, cWarn, cBad, cSoft;
    private TextView tState, tSub, tDown, tUp, tPing, tTotal, tInfo, tErr, tName, tTitle;
    private Button bMain;
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
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent i) {
        super.onNewIntent(i);
        handleIntent(i);
    }

    /** kronevpn://v1/... aus einem gescannten QR-Code oder Link */
    private void handleIntent(Intent i) {
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
        Button paste = button("Verbindungscode einfügen", false);
        paste.setOnClickListener(v -> askCode());
        c3.addView(paste);
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

    private void importCode(String code) {
        try {
            JSONObject c = new JSONObject(Native.parse(code));
            if (c.has("error")) {
                Toast.makeText(this, c.getString("error"), Toast.LENGTH_LONG).show();
                return;
            }
            boolean wasOn = KroneVpnService.handle != 0;
            KroneVpnService.prefs(this).edit().putString("code", c.getString("code")).apply();
            Toast.makeText(this, c.optString("title", "KroneVPN") + ": Code für „" + c.getString("name") + "“ gespeichert", Toast.LENGTH_SHORT).show();
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
            tName.setText(pc == null ? "Noch kein Verbindungscode" : "Gerät: " + pc.optString("name"));
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
        ui.post(tick);
    }

    @Override
    protected void onPause() {
        ui.removeCallbacks(tick);
        super.onPause();
    }
}
