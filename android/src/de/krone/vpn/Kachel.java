package de.krone.vpn;

import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.Icon;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

/**
 * Schnelleinstellungs-Kachel (oben aus dem Bildschirmrand ziehen): VPN an/aus, ohne die App zu oeffnen.
 * Fehlt noch etwas (Verbindungscode, VPN-Erlaubnis von Android), oeffnet sie stattdessen die App.
 * "Aktive" Kachel: Android fragt nicht staendig nach, der VPN-Dienst meldet Aenderungen selbst (aktualisieren()).
 */
public final class Kachel extends TileService {

    /** Zustand hat sich geaendert (verbunden, getrennt, pausiert) – Kachel neu zeichnen lassen */
    static void aktualisieren(Context c) {
        try {
            TileService.requestListeningState(c, new ComponentName(c, Kachel.class));
        } catch (Exception ignored) {
        }
    }

    @Override
    public void onStartListening() {
        zeigen();
    }

    @Override
    public void onTileAdded() {
        zeigen();
    }

    private void zeigen() {
        Tile t = getQsTile();
        if (t == null) return;
        boolean an = KroneVpnService.handle != 0;
        boolean pause = !an && !KroneVpnService.paused.isEmpty();
        // (die APK wird ohne R-Klasse gebaut: Symbol ueber den Namen)
        int ic = getResources().getIdentifier("ic_kachel", "drawable", getPackageName());
        if (ic != 0) t.setIcon(Icon.createWithResource(this, ic));
        t.setLabel(KroneVpnService.title(this));
        t.setState(an || pause ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        String sub = an ? "Verbunden" : pause ? "Pausiert (vertrautes Netz)" : "Aus";
        if (Build.VERSION.SDK_INT >= 29) t.setSubtitle(sub);
        t.setContentDescription(KroneVpnService.title(this) + ": " + sub);
        t.updateTile();
    }

    @Override
    public void onClick() {
        if (KroneVpnService.handle != 0 || !KroneVpnService.paused.isEmpty()) {
            // trennen (wie der Knopf in der App)
            startService(new Intent(this, KroneVpnService.class).setAction(KroneVpnService.ACTION_STOP));
            Tile t = getQsTile();
            if (t != null) {
                t.setState(Tile.STATE_INACTIVE);
                if (Build.VERSION.SDK_INT >= 29) t.setSubtitle("Aus");
                t.updateTile();
            }
            return;
        }
        boolean ohneCode = KroneVpnService.prefs(this).getString("code", null) == null;
        Intent prep = null;
        try {
            prep = VpnService.prepare(this);
        } catch (Exception ignored) {
        }
        if (ohneCode || prep != null) {
            // erst in der App einrichten bzw. die VPN-Erlaubnis bestaetigen
            appOeffnen();
            return;
        }
        KroneVpnService.lastError = "";
        // "jetzt": auch im vertrauten WLAN verbinden (wer auf die Kachel tippt, will das VPN)
        Intent i = new Intent(this, KroneVpnService.class).setAction(KroneVpnService.ACTION_JETZT).putExtra(KroneVpnService.EXTRA_FOREGROUND, true);
        try {
            startForegroundService(i);
        } catch (Exception e) {
            appOeffnen();
            return;
        }
        Tile t = getQsTile();
        if (t != null) {
            t.setState(Tile.STATE_ACTIVE);
            if (Build.VERSION.SDK_INT >= 29) t.setSubtitle("Verbinde …");
            t.updateTile();
        }
    }

    @SuppressWarnings("deprecation")
    private void appOeffnen() {
        Intent a = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        if (Build.VERSION.SDK_INT >= 34) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 20, a, PendingIntent.FLAG_IMMUTABLE));
        } else {
            startActivityAndCollapse(a);
        }
    }
}
