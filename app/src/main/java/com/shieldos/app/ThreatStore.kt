package com.shieldos.app

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject

enum class ThreatSource { CALL, SMS }

/** One flagged call or message, as shown in the live feed. */
data class ThreatEvent(
    val id: Long,
    val source: ThreatSource,
    val origin: String,
    val preview: String,
    val riskScore: Int,
    val reason: String,
    val level: RiskLevel,
    val timestamp: Long,
    val simulated: Boolean
)

/**
 * Tiny on-device event log. Keeps the last 50 flagged events plus two counters in
 * SharedPreferences and exposes them as StateFlows so the Compose UI updates live,
 * whether the event came from the call service, the SMS receiver or the demo buttons.
 */
object ThreatStore {

    private const val TAG = "ShieldOS"
    private const val PREFS = "shieldos_threat_store"
    private const val KEY_EVENTS = "events"
    private const val KEY_SCANNED = "scanned"
    private const val KEY_FLAGGED = "flagged"
    private const val MAX_EVENTS = 50

    private val _events = MutableStateFlow<List<ThreatEvent>>(emptyList())
    private val _scanned = MutableStateFlow(0)
    private val _flagged = MutableStateFlow(0)
    private var loaded = false

    val events: StateFlow<List<ThreatEvent>> = _events.asStateFlow()
    val scanned: StateFlow<Int> = _scanned.asStateFlow()
    val flagged: StateFlow<Int> = _flagged.asStateFlow()

    private fun prefs(context: Context): SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    @Synchronized
    fun load(context: Context) {
        if (loaded) return
        loaded = true

        val p = prefs(context)
        _scanned.value = p.getInt(KEY_SCANNED, 0)
        _flagged.value = p.getInt(KEY_FLAGGED, 0)

        val raw = p.getString(KEY_EVENTS, null) ?: return
        try {
            val array = JSONArray(raw)
            val restored = ArrayList<ThreatEvent>(array.length())
            for (i in 0 until array.length()) {
                val o = array.getJSONObject(i)
                restored.add(
                    ThreatEvent(
                        id = o.getLong("id"),
                        source = ThreatSource.valueOf(o.getString("source")),
                        origin = o.getString("origin"),
                        preview = o.getString("preview"),
                        riskScore = o.getInt("score"),
                        reason = o.getString("reason"),
                        level = RiskLevel.valueOf(o.getString("level")),
                        timestamp = o.getLong("time"),
                        simulated = o.optBoolean("simulated", false)
                    )
                )
            }
            _events.value = restored
        } catch (e: Exception) {
            Log.w(TAG, "Could not restore threat history", e)
            _events.value = emptyList()
        }
    }

    /**
     * Counts one scan. If the analysis is a threat it is added to the feed and the new
     * [ThreatEvent] is returned; safe results return null.
     */
    @Synchronized
    fun record(
        context: Context,
        source: ThreatSource,
        origin: String,
        preview: String,
        analysis: ScamAnalysis,
        simulated: Boolean
    ): ThreatEvent? {
        load(context)
        _scanned.value = _scanned.value + 1

        var event: ThreatEvent? = null
        if (analysis.isThreat) {
            val newest = _events.value.firstOrNull()?.id ?: 0L
            val id = maxOf(System.currentTimeMillis(), newest + 1)
            val created = ThreatEvent(
                id = id,
                source = source,
                origin = origin,
                preview = preview,
                riskScore = analysis.riskScore,
                reason = analysis.flaggedReason,
                level = analysis.level,
                timestamp = System.currentTimeMillis(),
                simulated = simulated
            )
            _events.value = (listOf(created) + _events.value).take(MAX_EVENTS)
            _flagged.value = _flagged.value + 1
            event = created
        }
        persist(context)
        return event
    }

    @Synchronized
    fun clear(context: Context) {
        load(context)
        _events.value = emptyList()
        _flagged.value = 0
        _scanned.value = 0
        persist(context)
    }

    private fun persist(context: Context) {
        val array = JSONArray()
        for (e in _events.value) {
            array.put(
                JSONObject().apply {
                    put("id", e.id)
                    put("source", e.source.name)
                    put("origin", e.origin)
                    put("preview", e.preview)
                    put("score", e.riskScore)
                    put("reason", e.reason)
                    put("level", e.level.name)
                    put("time", e.timestamp)
                    put("simulated", e.simulated)
                }
            )
        }
        prefs(context).edit()
            .putString(KEY_EVENTS, array.toString())
            .putInt(KEY_SCANNED, _scanned.value)
            .putInt(KEY_FLAGGED, _flagged.value)
            .apply()
    }
}
