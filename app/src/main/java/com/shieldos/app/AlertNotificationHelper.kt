package com.shieldos.app

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat

/** Builds the high-priority heads-up banners shown when a scam is detected. */
object AlertNotificationHelper {

    const val CHANNEL_ID = "shieldos_threat_alerts"

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Scam alerts",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Instant warnings when ShieldOS detects a scam call or SMS"
            enableVibration(true)
            vibrationPattern = longArrayOf(0, 250, 120, 250, 120, 500)
            lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            setShowBadge(true)
        }
        manager.createNotificationChannel(channel)
    }

    @SuppressLint("MissingPermission")
    fun showScamAlert(context: Context, event: ThreatEvent) {
        val app = context.applicationContext
        ensureChannel(app)

        val manager = NotificationManagerCompat.from(app)
        if (!manager.areNotificationsEnabled()) return

        val openApp = Intent(app, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentIntent = PendingIntent.getActivity(
            app,
            0,
            openApp,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val isCall = event.source == ThreatSource.CALL
        val high = event.level == RiskLevel.DANGEROUS

        val title = when {
            isCall && high -> "Scam call, ${event.riskScore}% risk"
            isCall -> "Suspicious call, ${event.riskScore}% risk"
            high -> "Phishing SMS, ${event.riskScore}% risk"
            else -> "Suspicious SMS, ${event.riskScore}% risk"
        }
        val summary = "${event.origin}: ${event.reason}"
        val advice = if (isCall) {
            "Do not share OTPs, PINs or card details. Never install an app or share your screen because a caller asks. Hang up if unsure."
        } else {
            "Do not tap the link or reply. Never share OTPs, PINs or card details. Banks never ask for them by SMS."
        }

        val notification = NotificationCompat.Builder(app, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(summary)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$summary\n\n$advice"))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(if (isCall) NotificationCompat.CATEGORY_CALL else NotificationCompat.CATEGORY_MESSAGE)
            .setColor(if (high) 0xFFFF3B30.toInt() else 0xFFFF9F0A.toInt())
            .setDefaults(NotificationCompat.DEFAULT_ALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setWhen(event.timestamp)
            .setShowWhen(true)
            .setAutoCancel(true)
            .setContentIntent(contentIntent)
            .build()

        manager.notify((event.id and 0x7FFFFFFFL).toInt(), notification)
    }
}
