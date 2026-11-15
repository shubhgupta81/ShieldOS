package com.shieldos.app

import android.content.Context
import android.util.Log

/**
 * The single path every event takes: analyze -> log -> alert.
 * The call service, the SMS receiver and the demo simulator all go through here,
 * so the demo exercises exactly the same code as a real scam.
 */
object ThreatPipeline {

    private const val TAG = "ShieldOS"
    private val WHITESPACE = Regex("\\s+")

    fun handleSms(context: Context, sender: String?, body: String, simulated: Boolean = false): ThreatEvent? {
        val analysis = ScamDetectorEngine.analyzeMessage(sender, body)
        val origin = if (sender.isNullOrBlank()) "Unknown sender" else sender.trim()
        val preview = body.replace(WHITESPACE, " ").trim().take(180)
        return conclude(context, ThreatSource.SMS, origin, preview, analysis, simulated)
    }

    fun handleCall(
        context: Context,
        number: String?,
        hiddenId: Boolean,
        verificationFailed: Boolean,
        simulated: Boolean = false
    ): ThreatEvent? {
        val analysis = ScamDetectorEngine.analyzeCall(number, hiddenId, verificationFailed)
        val origin = if (hiddenId || number.isNullOrBlank()) "Hidden number" else number.trim()
        return conclude(context, ThreatSource.CALL, origin, "Incoming call from $origin", analysis, simulated)
    }

    private fun conclude(
        context: Context,
        source: ThreatSource,
        origin: String,
        preview: String,
        analysis: ScamAnalysis,
        simulated: Boolean
    ): ThreatEvent? {
        val app = context.applicationContext
        val event = ThreatStore.record(app, source, origin, preview, analysis, simulated)
        Log.i(TAG, "${source.name} scanned: ${analysis.riskScore}% (${analysis.level.label}) ${analysis.flaggedReason}")
        if (event != null) {
            AlertNotificationHelper.showScamAlert(app, event)
        }
        return event
    }
}

/** Canned scams for the live college demo. Each tap rotates to the next scenario. */
object DemoScenarios {

    data class Sms(val sender: String, val body: String)
    data class Call(val number: String?, val hidden: Boolean, val verificationFailed: Boolean)

    private val smsSamples = listOf(
        Sms(
            "+91 98765 43210",
            "Dear HDFC customer, your KYC has expired today. Update immediately to avoid account suspension: " +
                "http://hdfc-kyc-update.xyz/verify or share your OTP with our executive."
        ),
        Sms(
            "VK-UPIPAY",
            "Refund of Rs 4,999 is pending. Open the collect request and enter your UPI PIN to receive " +
                "the money now. Act fast: bit.ly/refund-upi"
        ),
        Sms(
            "+44 7700 900123",
            "Congratulations! You have won Rs 25,00,000 in the KBC Lucky Draw. To claim your prize pay the " +
                "Rs 12,500 processing fee and WhatsApp 9812345678."
        ),
        Sms(
            "+91 70012 34567",
            "TRAI Notice: your mobile number will be disconnected within 2 hours due to illegal activity. " +
                "Call 9811122233 immediately to avoid legal action."
        ),
        Sms(
            "+91 63000 11223",
            "Work from home! Earn Rs 5000 daily by liking YouTube videos. Join our Telegram group: t.me/earnnow99"
        )
    )

    private val callSamples = listOf(
        Call("+92 321 4098762", hidden = false, verificationFailed = true),
        Call("+84 98 7654 3210", hidden = false, verificationFailed = false),
        Call(null, hidden = true, verificationFailed = true)
    )

    private var smsIndex = 0
    private var callIndex = 0

    @Synchronized
    fun nextSms(): Sms = smsSamples[smsIndex++ % smsSamples.size]

    @Synchronized
    fun nextCall(): Call = callSamples[callIndex++ % callSamples.size]
}
