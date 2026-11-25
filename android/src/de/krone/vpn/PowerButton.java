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
 * Power-Zeichen. Gezeichnet auf einem 156er-Raster wie am PC und auf die Groesse des Knopfs skaliert.
 * Animationen: Farbe blendet weich um, beim Verbinden laeuft ein Bogen um den Ring und das Leuchten pulsiert,
 * verbunden "atmet" das Leuchten ruhig, Druecken federt den Knopf ein, beim Verbinden ploppt er kurz auf.
 */
final class PowerButton extends View {
    static final int OFF = 0, CONNECTING = 1, CONNECTED = 2, DISCONNECTING = 3;

    private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final RectF r = new RectF();
    private final long t0 = SystemClock.uptimeMillis();
    private int state = OFF;
    private int cCard, cLine, cMute, cAcc, cOk, cWarn, cHover;
    /** aktuelle Farbe (blendet bei Zustandswechsel um) */
    private int color;
    private float scale = 1f;
    private ValueAnimator colorAnim, scaleAnim;
    private boolean down;

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

    int getState() {
        return state;
    }

    void setState(int s) {
        if (s == state) return;
        int old = state;
        state = s;
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
                down = true;
                animateScale(0.93f, 110, new DecelerateInterpolator(), null);
                invalidate();
                return true;
            case MotionEvent.ACTION_UP:
                boolean inside = e.getX() >= 0 && e.getY() >= 0 && e.getX() <= getWidth() && e.getY() <= getHeight();
                down = false;
                animateScale(1f, 380, new OvershootInterpolator(3f), null);
                if (inside) {
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
        int want = (int) (172 * getResources().getDisplayMetrics().density);
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
        float k = Math.min(w, h) / 156f; // Raster der PC-App: 156 x 156, Knopf-Radius 60
        float cx = w / 2f, cy = h / 2f;
        float t = (SystemClock.uptimeMillis() - t0) / 1000f;
        cv.save();
        cv.scale(scale, scale, cx, cy);
        p.setStrokeCap(Paint.Cap.BUTT);

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
        } else if (state == CONNECTING || state == DISCONNECTING) {
            p.setColor(alpha(color, 0.18f));
            cv.drawCircle(cx, cy, 60 * k, p);
            p.setColor(color);
            p.setStrokeCap(Paint.Cap.ROUND);
            float a0 = (float) Math.toDegrees(t * 4) % 360f;
            cv.drawArc(r, a0, 92f, false, p);
            p.setStrokeCap(Paint.Cap.BUTT);
        } else {
            p.setColor(down ? alpha(cAcc, 0.7f) : cLine);
            cv.drawCircle(cx, cy, 60 * k, p);
        }
        // Power-Zeichen: Bogen (offen nach oben) + Strich
        int sym = state == OFF ? (down ? cAcc : cMute) : color;
        p.setColor(sym);
        p.setStrokeWidth(5.5f * k);
        p.setStrokeCap(Paint.Cap.ROUND);
        r.set(cx - 24 * k, cy + 3 * k - 24 * k, cx + 24 * k, cy + 3 * k + 24 * k);
        float luecke = (float) Math.toDegrees(0.75);
        cv.drawArc(r, -90f + luecke, 360f - 2 * luecke, false, p);
        cv.drawLine(cx, cy - 26 * k, cx, cy - 4 * k, p);
        cv.restore();

        if (state != OFF || (colorAnim != null && colorAnim.isRunning())) postInvalidateOnAnimation();
    }
}
