package com.shieldos.app

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log

/**
 * Scans incoming SMS, WhatsApp, and Telegram message notifications in real time
 * without requiring restricted READ_SMS permissions that trigger Google Play Protect.
 */
class ScamNotificationService : NotificationListenerService() {

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        if (sbn == null) return
        val pkg = sbn.packageName ?: return

        // Never scan our own warning notifications
        if (pkg == applicationContext.packageName) return

        val extras = sbn.notification?.extras ?: return
        val sender = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = (extras.getCharSequence(Notification.EXTRA_BIG_TEXT)
            ?: extras.getCharSequence(Notification.EXTRA_TEXT))?.toString().orEmpty()

        if (text.length < 6) return

        try {
            ThreatPipeline.handleSms(applicationContext, sender.ifBlank { "Incoming Message" }, text)
        } catch (t: Throwable) {
            Log.e("ShieldOS", "Notification scan failed", t)
        }
    }
}
