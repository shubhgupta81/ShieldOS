package com.shieldos.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

/** Receives every incoming SMS, scans it on the spot and raises a warning if it looks like a scam. */
class SmsFraudReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        try {
            val parts = Telephony.Sms.Intents.getMessagesFromIntent(intent)
            if (parts.isNullOrEmpty()) return

            // Long texts arrive as several PDUs from the same sender: glue them back together.
            parts.groupBy { it.originatingAddress.orEmpty() }.forEach { (sender, pieces) ->
                val body = pieces.joinToString(separator = "") { it.messageBody.orEmpty() }
                ThreatPipeline.handleSms(context, sender, body)
            }
        } catch (t: Throwable) {
            Log.e("ShieldOS", "SMS scan failed", t)
        }
    }
}
