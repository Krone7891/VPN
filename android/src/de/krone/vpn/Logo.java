package de.krone.vpn;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.Icon;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;

/**
 * Eigenes Logo des Servers. Der VPN-Kern holt es beim Verbinden durch den Tunnel, wenn es neu ist, und legt es in
 * {@link #dir} ab (logo.png 256 x 256 + logo.id). Die App zeigt es dann im Kopf, in der Benachrichtigung und als
 * Symbol einer Verknuepfung auf dem Startbildschirm.
 *
 * Das Symbol der App selbst (im App-Menue) kann Android nicht austauschen – das legt der Hersteller beim Bauen fest.
 * Deshalb gibt es die Verknuepfung: einmal anlegen, danach bekommt sie bei jedem neuen Logo von selbst das neue Bild.
 */
final class Logo {
    static final String SHORTCUT = "logo";

    private Logo() {
    }

    static File dir(Context c) {
        return new File(c.getFilesDir(), "logo");
    }

    /** Kennung des gespeicherten Logos ("" = keins, dann die Krone) */
    static String id(Context c) {
        try {
            return new String(Files.readAllBytes(new File(dir(c), "logo.id").toPath()), StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return "";
        }
    }

    static Bitmap bitmap(Context c) {
        if (id(c).isEmpty()) return null;
        try {
            return BitmapFactory.decodeFile(new File(dir(c), "logo.png").getAbsolutePath());
        } catch (Exception e) {
            return null;
        }
    }

    static boolean canPin(Context c) {
        try {
            ShortcutManager sm = c.getSystemService(ShortcutManager.class);
            return sm != null && sm.isRequestPinShortcutSupported();
        } catch (Exception e) {
            return false;
        }
    }

    private static Icon icon(Context c) {
        Bitmap b = bitmap(c);
        return b != null ? Icon.createWithBitmap(b) : Icon.createWithResource(c, c.getApplicationInfo().icon);
    }

    private static ShortcutInfo info(Context c, String label) {
        Intent open = new Intent(c, MainActivity.class).setAction(Intent.ACTION_MAIN);
        String l = label == null || label.trim().isEmpty() ? "KroneVPN" : label.trim();
        return new ShortcutInfo.Builder(c, SHORTCUT).setShortLabel(l).setLongLabel(l).setIcon(icon(c)).setIntent(open).build();
    }

    /** Verknuepfung mit dem Logo auf den Startbildschirm legen (Android fragt einmal nach) */
    static boolean pin(Activity a, String label) {
        try {
            ShortcutManager sm = a.getSystemService(ShortcutManager.class);
            return sm != null && sm.requestPinShortcut(info(a, label), null);
        } catch (Exception e) {
            return false;
        }
    }

    /** schon angelegte Verknuepfung bekommt das aktuelle Logo (oder wieder die Krone) */
    static void refreshShortcut(Context c, String label) {
        try {
            ShortcutManager sm = c.getSystemService(ShortcutManager.class);
            if (sm == null) return;
            boolean pinned = false;
            for (ShortcutInfo s : sm.getPinnedShortcuts()) if (SHORTCUT.equals(s.getId())) pinned = true;
            if (pinned) sm.updateShortcuts(Collections.singletonList(info(c, label)));
        } catch (Exception ignored) {
        }
    }
}
