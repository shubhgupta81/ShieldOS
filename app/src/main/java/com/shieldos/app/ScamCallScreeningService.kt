package com.shieldos.app

import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import android.telecom.CallScreeningService.CallResponse
import android.telecom.Connection
import android.telecom.TelecomManager
import android.util.Log

/**
 * Android calls this for every incoming call once ShieldOS holds the Call Screening role.
 * ShieldOS never blocks a call on its own: it scores the caller, logs the event, raises a
 * warning banner, and always lets the call through so a false positive cannot hide a real call.
 */
class ScamCallScreeningService : CallScreeningService() {

    override fun onScreenCall(callDetails: Call.Details) {
        try {
            val incoming = Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
                callDetails.callDirection == Call.Details.DIRECTION_INCOMING

            if (incoming) {
                val number = callDetails.handle?.schemeSpecificPart
                val hidden = number.isNullOrBlank() ||
                    callDetails.handlePresentation != TelecomManager.PRESENTATION_ALLOWED
                val spoofed = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R &&
                    callDetails.callerNumberVerificationStatus == Connection.VERIFICATION_STATUS_FAILED

                ThreatPipeline.handleCall(applicationContext, number, hidden, spoofed)
            }
        } catch (t: Throwable) {
            Log.e("ShieldOS", "Call screening failed", t)
        }

        // An empty response means: allow the call, ring normally, keep it in the call log.
        respondToCall(callDetails, CallResponse.Builder().build())
    }
}
