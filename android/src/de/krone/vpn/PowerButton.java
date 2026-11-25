package de.krone.vpn;

import android.animation.ArgbEvaluator;
import android.animation.ValueAnimator;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.os.SystemClock;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.OvershootInterpolator;

/**
 * Grosser runder Ein/Aus-Knopf – dasselbe Symbol wie in der PC-App (gui.rs, fn schalter): Leuchten, Ring und
 * Power-Zeichen. Gezeichnet auf einem 184er-Raster wie am PC und auf die Groesse des Knopfs skaliert.
 * Animationen: Farbe blendet weich um, beim Verbinden laeuft ein Bogen um den Ring und das Leuchten pulsiert,
 * verbunden "atmet" das Leuchten ruhig, Druecken federt den Knopf ein, beim Verbinden ploppt er kurz auf.
 * Hat die App den Fokus (setLebhaft), kommt mehr dazu: Wellen laufen vom Knopf weg, ein Lichtpunkt kreist um den
 * Ring, das Power-Zeichen zeichnet sich beim Verbinden neu, Tippen schickt eine Welle los und aus lädt der Knopf
 * sanft zum Tippen ein, und um den Knopf dreht sich ein Wirbel (Tornado): beim Verbinden schnell nach innen,
 * beim Trennen rueckwaerts nach aussen, verbunden ruhig. Ohne Fokus (oder mit "Animationen aus" in Android) bleibt es ruhig und spart Akku.
 */
final class PowerButton extends View {
    static final int OFF = 0, CONNECTING = 1, CONNECTED = 2, DISCONNECTING = 3;

    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF r = new RectF();
    private static final ArgbEvaluator MISCH = new ArgbEvaluator();
    private final long t0 = SystemClock.uptimeMillis();
    private int state = OFF;
    private int cCard, cLine, cMute, cAcc, cOk, cWarn, cHover;
    /** aktuelle Farbe (blendet bei Zustandswechsel um) */
    private int color;
    private float scale = 1f;
    private ValueAnimator colorAnim, scaleAnim;
    private boolean down;
    /** App sichtbar mit Fokus: mehr Animation */
    private boolean lebhaft;
    /** Zeitpunkt des letzten Tippens (Welle) und des letzten Zustandswechsels */
    private long klick = -1, seit = -1;
    /** Wirbel (Tornado): Drehung, Sog, aktuelle Drehzahl, Staerke, Sog-Tempo; Zeit des letzten Bilds */
    private float wDreh, wSog, wW, wSt, wZug;
    private long wT = -1;

    PowerButton(Context c) {
        super(c);
        setClickable(true);
        setFocusable(true);
        setContentDescription("Verbinden");
    }

    void setColors(int card, int line, int mute, int acc, int ok, int warn, boolean dark) {
        cCard = card;
        cLine = line;
        cMute = mute;
        cAcc = acc;
        cOk = ok;
        cWarn = warn;
        cHover = dark ? 0xFF1F232C : 0xFFF0F3F8;
        color = target(state);
        invalidate();
    }

    private int target(int s) {
        switch (s) {
            case CONNECTED: return cOk;
            case CONNECTING: return cAcc;
            case DISCONNECTING: return cWarn;
            default: return cMute;
        }
    }

    /** App hat den Fokus: lebhafter animieren (nur wenn Animationen in Android an sind) */
    void setLebhaft(boolean b) {
        boolean an = b && (android.os.Build.VERSION.SDK_INT < 26 || ValueAnimator.areAnimatorsEnabled());
        if (an == lebhaft) return;
        lebhaft = an;
        invalidate();
    }

    int getState() {
        return state;
    }

    void setState(int s) {
        if (s == state) return;
        int old = state;
        state = s;
        seit = SystemClock.uptimeMillis();
        setContentDescription(s == OFF ? "Verbinden" : s == DISCONNECTING ? "Wird getrennt" : "Trennen");
        if (colorAnim != null) colorAnim.cancel();
        colorAnim = ValueAnimator.ofObject(new ArgbEvaluator(), color, target(s));
        colorAnim.setDuration(380);
        colorAnim.addUpdateListener(a -> {
            color = (int) a.getAnimatedValue();
            invalidate();
        });
        colorAnim.start();
        // verbunden: kurz aufploppen und spuerbar bestaetigen
        if (s == CONNECTED && old != CONNECTED) {
            animateScale(1.07f, 160, new DecelerateInterpolator(), () -> animateScale(1f, 420, new OvershootInterpolator(2.2f), null));
            performHapticFeedback(HapticFeedbackConstants.CONFIRM);
        }
        invalidate();
    }

    private void animateScale(float to, long ms, android.animation.TimeInterpolator ip, Runnable then) {
        if (scaleAnim != null) scaleAnim.cancel();
        scaleAnim = ValueAnimator.ofFloat(scale, to);
        scaleAnim.setDuration(ms);
        scaleAnim.setInterpolator(ip);
        scaleAnim.addUpdateListener(a -> {
            scale = (float) a.getAnimatedValue();
            invalidate();
        });
        if (then != null) {
            scaleAnim.addListener(new android.animation.AnimatorListenerAdapter() {
                boolean cancelled;

                @Override
                public void onAnimationCancel(android.animation.Animator a) {
                    cancelled = true;
                }

                @Override
                public void onAnimationEnd(android.animation.Animator a) {
                    if (!cancelled) then.run();
                }
            });
        }
        scaleAnim.start();
    }

    @Override
    public boolean onTouchEvent(MotionEvent e) {
        if (!isEnabled() || state == DISCONNECTING) return false;
        switch (e.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                // nur der Knopf selbst (Radius 60 + etwas Rand), nicht der Wirbel drumherum
                float kk = Math.min(getWidth(), getHeight()) / 184f;
                if (Math.hypot(e.getX() - getWidth() / 2f, e.getY() - getHeight() / 2f) > 68 * kk) return false;
                down = true;
                animateScale(0.93f, 110, new DecelerateInterpolator(), null);
                invalidate();
                return true;
            case MotionEvent.ACTION_UP:
                boolean inside = e.getX() >= 0 && e.getY() >= 0 && e.getX() <= getWidth() && e.getY() <= getHeight();
                down = false;
                animateScale(1f, 380, new OvershootInterpolator(3f), null);
                if (inside) {
                    klick = SystemClock.uptimeMillis();
                    performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY);
                    performClick();
                }
                invalidate();
                return true;
            case MotionEvent.ACTION_CANCEL:
                down = false;
                animateScale(1f, 250, new DecelerateInterpolator(), null);
                invalidate();
                return true;
        }
        return super.onTouchEvent(e);
    }

    @Override
    public boolean performClick() {
        return super.performClick();
    }

    @Override
    protected void onMeasure(int wSpec, int hSpec) {
        int want = (int) (203 * getResources().getDisplayMetrics().density); // Knopf wie bisher, plus Platz fuer den Wirbel
        int w = resolveSize(want, wSpec), h = resolveSize(want, hSpec);
        int s = Math.min(w, h);
        setMeasuredDimension(s, s);
    }

    private static int alpha(int c, float a) {
        return Color.argb(Math.round(Color.alpha(c) * Math.max(0f, Math.min(1f, a))), Color.red(c), Color.green(c), Color.blue(c));
    }

    @Override
    protected void onDraw(Canvas cv) {
        float w = getWidth(), h = getHeight();
        float k = Math.min(w, h) / 184f; // Raster der PC-App: 184 x 184, Knopf-Radius 60
        float cx = w / 2f, cy = h / 2f;
        long now = SystemClock.uptimeMillis();
        float t = (now - t0) / 1000f;
        // aus: lädt sanft zum Tippen ein (leichtes Atmen, alle 4 s eine leise Welle)
        float einladen = lebhaft && state == OFF ? 0.5f - 0.5f * (float) Math.cos(t * 2 * Math.PI / 4) : 0f;
        float sc = scale * (1f + 0.012f * einladen);
        cv.save();
        cv.scale(sc, sc, cx, cy);
        p.setStrokeCap(Paint.Cap.BUTT);

        // Wellen, die vom Knopf weglaufen
        boolean welle = false;
        if (lebhaft) {
            p.setStyle(Paint.Style.STROKE);
            if (state == CONNECTED) {
                for (int i = 0; i < 2; i++) welle(cv, cx, cy, k, ((t + i * 1.4f) % 2.8f) / 2.8f, color, 0.4f, 2.5f);
            } else if (state == CONNECTING || state == DISCONNECTING) {
                // dort dreht sich der Wirbel
            } else {
                float x = ((t + 2f) % 4f) / 1.8f; // startet, wenn das Atmen am staerksten ist
                if (x < 1f) welle(cv, cx, cy, k, x, cAcc, 0.16f, 2f);
            }
        }
        if (klick > 0 && now - klick < 600) {
            p.setStyle(Paint.Style.STROKE);
            welle(cv, cx, cy, k, (now - klick) / 600f, state == OFF ? cAcc : color, 0.55f, 3.5f);
            welle = true;
        }

        // Leuchten (verbinden: pulsiert, verbunden: atmet ruhig)
        if (state != OFF) {
            float puls = state == CONNECTED ? 0.55f + 0.25f * (float) Math.sin(t * 1.7) : 0.5f + 0.5f * (float) Math.sin(t * 3);
            p.setStyle(Paint.Style.FILL);
            float[][] ringe = {{77, 0.05f}, {71, 0.08f}, {65, 0.12f}};
            for (float[] g : ringe) {
                p.setColor(alpha(color, g[1] * (0.6f + 0.4f * puls) * 1.6f));
                cv.drawCircle(cx, cy, g[0] * k, p);
            }
        }
        // Wirbel (Tornado): Spiralarme drehen sich um den Knopf, Teilchen werden hineingezogen
        boolean wirbel = wirbelWeiter(now);
        if (wSt > 0.01f) {
            int wf = state == OFF ? (Integer) MISCH.evaluate(0.5f, cMute, cAcc) : color;
            int hell = (Integer) MISCH.evaluate(0.3f, wf, 0xFFFFFFFF);
            p.setStyle(Paint.Style.STROKE);
            p.setStrokeCap(Paint.Cap.ROUND);
            for (int arm = 0; arm < 3; arm++) {
                double a0 = wDreh + arm * 2 * Math.PI / 3;
                int n = 16;
                for (int j = 0; j < n; j++) {
                    float s0 = j / (float) n, s1 = (j + 1) / (float) n, sm = (s0 + s1) / 2;
                    float fluss = 0.6f + 0.4f * (float) Math.sin(2 * Math.PI * (sm * 2 + wSog * 3));
                    p.setStrokeWidth((2.5f - s0) * k);
                    p.setColor(alpha(wf, wSt * 0.7f * (float) Math.sin(Math.PI * sm) * fluss));
                    float r0 = (62 + 29 * s0) * k, r1 = (62 + 29 * s1) * k;
                    double b0 = a0 - s0 * 2.6, b1 = a0 - s1 * 2.6;
                    cv.drawLine(cx + r0 * (float) Math.cos(b0), cy + r0 * (float) Math.sin(b0), cx + r1 * (float) Math.cos(b1), cy + r1 * (float) Math.sin(b1), p);
                }
            }
            p.setStrokeCap(Paint.Cap.BUTT);
            p.setStyle(Paint.Style.FILL);
            for (int i = 0; i < 34; i++) {
                float q = wSog + i * 0.618034f;
                q -= (float) Math.floor(q);
                double a = i * 2.399963 + wDreh + q * 2.5;
                float rr = (91 - 29 * q) * k;
                p.setColor(alpha(hell, wSt * 0.9f * (float) Math.sin(Math.PI * q)));
                cv.drawCircle(cx + rr * (float) Math.cos(a), cy + rr * (float) Math.sin(a), (1f + 1.5f * (1 - q)) * k, p);
            }
        }
        // Knopf
        p.setStyle(Paint.Style.FILL);
        p.setColor(down && state == OFF ? cHover : cCard);
        cv.drawCircle(cx, cy, 60 * k, p);
        p.setStyle(Paint.Style.STROKE);
        p.setStrokeWidth(1 * k);
        p.setColor(cLine);
        cv.drawCircle(cx, cy, 60 * k, p);
        // Ring
        p.setStrokeWidth(5 * k);
        r.set(cx - 60 * k, cy - 60 * k, cx + 60 * k, cy + 60 * k);
        if (state == CONNECTED) {
            p.setColor(color);
            cv.drawCircle(cx, cy, 60 * k, p);
            if (lebhaft) {
                // Lichtpunkt mit Schweif kreist langsam um den Ring
                int hell = (Integer) MISCH.evaluate(0.65f, color, 0xFFFFFFFF);
                float kopf = (float) Math.toDegrees(t * 1.3) % 360f;
                // uebereinander gelegte Boegen, die alle am Kopf enden: vorne hell, hinten weich auslaufend
                p.setColor(alpha(hell, 0.16f));
                for (int i = 1; i <= 10; i++) cv.drawArc(r, kopf - i * 6.3f, i * 6.3f, false, p);
            }
        } else if (state == CONNECTING || state == DISCONNECTING) {
            p.setColor(alpha(color, 0.18f));
            cv.drawCircle(cx, cy, 60 * k, p);
            p.setColor(color);
            p.setStrokeCap(Paint.Cap.ROUND);
            float a0 = (float) Math.toDegrees(t * 4) % 360f;
            // lebhaft: Bogen wird laenger und kuerzer (wie ein Ladekreis)
            float lang = lebhaft ? 30f + 190f * (0.5f - 0.5f * (float) Math.cos(t * 2.4)) : 92f;
            cv.drawArc(r, a0, lang, false, p);
            p.setStrokeCap(Paint.Cap.BUTT);
        } else {
            int ring = down ? alpha(cAcc, 0.7f) : (Integer) MISCH.evaluate(0.35f * einladen, cLine, cAcc);
            p.setColor(ring);
            cv.drawCircle(cx, cy, 60 * k, p);
        }
        // Power-Zeichen: Bogen (offen nach oben) + Strich
        int sym = state == OFF ? (down ? cAcc : cMute) : color;
        p.setColor(sym);
        p.setStrokeWidth(5.5f * k);
        p.setStrokeCap(Paint.Cap.ROUND);
        r.set(cx - 24 * k, cy + 3 * k - 24 * k, cx + 24 * k, cy + 3 * k + 24 * k);
        float luecke = (float) Math.toDegrees(0.75);
        // lebhaft: nach dem Verbinden zeichnet sich das Zeichen von oben her neu (Strich, dann Bogen von beiden Seiten)
        float neu = lebhaft && state == CONNECTED && seit > 0 ? Math.min(1f, (now - seit) / 700f) : 1f;
        neu = 1f - (1f - neu) * (1f - neu) * (1f - neu);
        float voll = 360f - 2 * luecke;
        if (neu >= 1f) {
            cv.drawArc(r, -90f + luecke, voll, false, p);
        } else {
            cv.drawArc(r, -90f + luecke, voll / 2 * neu, false, p);
            cv.drawArc(r, -90f - luecke, -voll / 2 * neu, false, p);
        }
        cv.drawLine(cx, cy - 26 * k, cx, cy - 26 * k + 22 * k * Math.max(0.05f, Math.min(1f, neu * 1.6f)), p);
        cv.restore();

        if (state != OFF || lebhaft || welle || wirbel || (colorAnim != null && colorAnim.isRunning())) postInvalidateOnAnimation();
    }

    /**
     * Wirbel weiterdrehen: Drehzahl, Sog und Staerke gleiten weich zum Ziel (kein Ruckeln beim Zustandswechsel).
     * Ohne Fokus blendet er aus. true = noch sichtbar (weiter zeichnen)
     */
    private boolean wirbelWeiter(long now) {
        float dt = wT < 0 ? 0f : Math.min(0.1f, (now - wT) / 1000f);
        wT = now;
        float st, w, zug;
        switch (state) {
            case CONNECTING: st = 1f; w = 4.5f; zug = 0.9f; break;
            case DISCONNECTING: st = 0.8f; w = -3.5f; zug = -0.7f; break;
            case CONNECTED: st = 0.6f; w = 1.1f; zug = 0.22f; break;
            default: st = 0.3f; w = 0.7f; zug = 0.15f;
        }
        if (!lebhaft) st = 0f;
        float f = Math.min(1f, dt * 2.5f);
        wW += (w - wW) * f;
        wSt += (st - wSt) * f;
        wZug += (zug - wZug) * f;
        wDreh = (float) ((wDreh + wW * dt) % (2 * Math.PI));
        wSog += wZug * dt;
        wSog -= (float) Math.floor(wSog);
        return wSt > 0.01f;
    }

    /** eine Welle: x = 0..1 (Fortschritt), laeuft vom Ring (60) nach aussen bis 77 und blendet aus */
    private void welle(Canvas cv, float cx, float cy, float k, float x, int c, float a, float breite) {
        float e = 1f - (1f - x) * (1f - x);
        p.setStrokeWidth(breite * k * (1f - 0.5f * x));
        p.setColor(alpha(c, a * (1f - x) * (1f - x)));
        cv.drawCircle(cx, cy, (60f + 17f * e) * k, p);
    }
}
