package com.shieldos.app

/** Traffic-light level derived from a 0-100 risk score. */
enum class RiskLevel(val label: String) {
    SAFE("Safe"),
    SUSPICIOUS("Suspicious"),
    DANGEROUS("High risk")
}

/**
 * Result of scanning one SMS or one call.
 *
 * @property riskScore 0-100 percent risk.
 * @property flaggedReason short human-readable explanation (top signals).
 * @property signals every signal that fired, strongest first.
 */
data class ScamAnalysis(
    val riskScore: Int,
    val flaggedReason: String,
    val signals: List<String>
) {
    val level: RiskLevel
        get() = when {
            riskScore >= ScamDetectorEngine.DANGER_THRESHOLD -> RiskLevel.DANGEROUS
            riskScore >= ScamDetectorEngine.SUSPICIOUS_THRESHOLD -> RiskLevel.SUSPICIOUS
            else -> RiskLevel.SAFE
        }

    val isThreat: Boolean
        get() = level != RiskLevel.SAFE
}

/**
 * 100% offline heuristic + regex scam analyzer. No network, no cloud, no ML model:
 * every decision comes from the weighted rules below, so it is easy to read, tune
 * and explain.  Each rule that matches adds its weight; the total is capped at 98.
 *
 *   score >= 70  -> High risk
 *   score >= 40  -> Suspicious
 *   otherwise    -> Safe
 */
object ScamDetectorEngine {

    const val SUSPICIOUS_THRESHOLD = 40
    const val DANGER_THRESHOLD = 70

    private const val MAX_SCORE = 98
    private const val MAX_BODY_CHARS = 4000

    /** Country code (without +) treated as "home". Everything else is international. */
    private const val HOME_COUNTRY_CODE = "91"

    /** Bank / payment / government brand fragments used for look-alike link detection. */
    private const val BANK_ALT =
        "sbi|hdfc|icici|axis|kotak|pnb|bob|idfc|yesbank|paytm|phonepe|gpay|npci|rbi|upi|epfo|uidai|irctc|netbank|kyc|bank"

    private class Rule(val label: String, val weight: Int, pattern: String) {
        val regex: Regex = Regex(pattern, setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
    }

    // ------------------------------------------------------------------ message rules

    private val messageRules: List<Rule> = listOf(

        Rule(
            "KYC expiry scam", 35,
            """\b(?:e-?kyc|re-?kyc|video kyc|kyc|know your customer)\b.{0,80}?\b(?:expire[sd]?|expiry|expiring|pending|suspen(?:d|ded|sion)|block(?:ed|ing)?|incomplete|invalid|deactivat(?:e|ed)|not (?:updated|completed|verified)|updat(?:e|ing)|verify|verification|complete|renew)\b|\b(?:update|complete|verify|renew|submit|finish)\b.{0,40}?\b(?:e-?kyc|kyc|know your customer)\b"""
        ),

        Rule(
            "Account block or suspension threat", 30,
            """\b(?:account|a/c|acct|card|sim|wallet|upi id|net ?banking)\b.{0,50}?\b(?:block(?:ed|ing)?|suspen(?:d|ded|sion)|deactivat(?:e|ed|ion)|freez(?:e|ing)|frozen|clos(?:e|ed|ure)|locked|restricted|terminated|disconnect(?:ed|ion)?)\b"""
        ),

        Rule(
            "Asks for OTP, PIN or card details", 45,
            """\b(?:share|send|tell|provide|give|forward|reply(?: with)?|read out|disclose|submit|reveal|confirm)\b.{0,30}?\b(?:otp|one[- ]time password|cvv|cvc|upi[- ]?pin|m-?pin|atm pin|card number|card details|net ?banking password|password|pin)\b"""
        ),

        Rule(
            "UPI collect or refund trap", 35,
            """\b(?:enter|put|type|input|share|approve)\b.{0,25}?\b(?:upi[- ]?pin|m-?pin|pin)\b.{0,50}?\b(?:receive|refund|cashback|credit|claim|get)\b|\b(?:receive|refund|cashback|claim)\b.{0,60}?\b(?:enter|put|type|input)\b.{0,25}?\b(?:upi[- ]?pin|pin)\b|\b(?:collect request|payment request|approve (?:the )?request|accept (?:the )?request|scan (?:the |this )?qr(?: code)?)\b.{0,60}?\b(?:receive|refund|cashback|prize|reward|claim|get)\b"""
        ),

        Rule(
            "Lottery or prize fraud", 45,
            """\b(?:lottery|lucky draw|lucky winner|jackpot|kbc)\b|\byou(?:\u0027ve|\u2019ve| have)? (?:been selected|won)\b.{0,40}?(?:\brs\b|\binr\b|\u20B9|\busd\b|\blakh|\bcrore|\bprize|\bcar\b|\biphone|\bgift|\bcash\b|\d{4,})|\bclaim (?:your |the )?(?:prize|reward|gift|cashback)\b|\bfree (?:iphone|gift|recharge)\b"""
        ),

        Rule(
            "Advance-fee or processing-charge demand", 30,
            """\b(?:processing|registration|clearance|customs|release|delivery|handling|insurance|gst|tax|activation|verification) (?:fees?|charges?|amount|deposit)\b|\b(?:pay|deposit|transfer|send)\b.{0,40}?\bto (?:claim|release|receive|unlock|activate)\b"""
        ),

        Rule(
            "Fake authority or digital-arrest threat", 45,
            """\b(?:customs|cbi|narcotics|ncb|trai|rbi|income tax|enforcement directorate|cyber ?crime|police|court|fedex|dhl|courier|parcel|telecom department)\b.{0,100}?\b(?:seized|illegal|drugs?|contraband|arrest(?:ed)?|warrant|money laundering|legal action|penalty|case (?:registered|filed)|(?:sim|number|mobile number) (?:will be )?(?:blocked|disconnected|deactivated)|digital arrest|video call)\b"""
        ),

        Rule(
            "Aadhaar or PAN update scam", 35,
            """\b(?:pan(?: card)?|aadhaar|aadhar|uidai)\b.{0,50}?\b(?:updat(?:e|ed|ion)|link(?:ed|ing)?|verif(?:y|ication)|suspen(?:d|ded|sion)|block(?:ed)?|expire[sd]?|invalid|deactivat(?:e|ed)|inoperative)\b"""
        ),

        Rule(
            "Fake job or task-earning offer", 35,
            """\b(?:work from home|part[- ]?time (?:job|work)|online (?:job|work)|data entry|task (?:job|work)|like (?:and|&) subscribe|youtube (?:likes?|task)|telegram (?:group|channel)|whatsapp group)\b.{0,100}?(?:\b(?:earn|income|salary|commission|per day|daily|weekly)\b|\u20B9|\brs\.?\s?\d|\binr\b)|\b(?:earn|make)\b.{0,20}?(?:\u20B9|\brs\.?|\binr\b)\s?\d[\d,]*.{0,30}?\b(?:per day|daily|a day|per hour|weekly)\b"""
        ),

        Rule(
            "Fake utility or SIM disconnection notice", 30,
            """\b(?:electricity|power|gas|water|broadband|dth|fastag|sim)\b.{0,30}?\b(?:bill|connection|supply|service|recharge|kyc|wallet)\b.{0,60}?\b(?:disconnect(?:ed|ion)?|cut|stopped|suspen(?:d|ded|sion)|expire[sd]?|tonight|unpaid|overdue|block(?:ed)?|deactivat(?:e|ed))\b"""
        ),

        Rule(
            "Predatory instant-loan offer", 30,
            """\b(?:instant|pre-?approved|quick|easy) (?:personal )?loan\b.{0,80}?\b(?:no (?:documents?|cibil|collateral|income proof)|apply now|click|download|app|link|approved)\b|\bloan (?:approved|sanctioned)\b.{0,60}?\b(?:processing fee|click|link|apk|app)\b"""
        ),

        Rule(
            "Malicious APK or remote-access app", 50,
            """\.apk\b|\b(?:anydesk|teamviewer|quicksupport|rustdesk|airdroid|ammyy)\b"""
        ),

        Rule(
            "Look-alike bank or government link", 35,
            """(?:https?://|www\.)[^\s/]*(?:${BANK_ALT})[^\s/]*(?:-|\d)[^\s/]*\.[a-z]{2,}|(?:https?://|www\.)[^\s/]*(?:-|\d)[^\s/]*(?:${BANK_ALT})[^\s/]*\.[a-z]{2,}|\b[a-z0-9-]*(?:${BANK_ALT})[a-z0-9-]*-[a-z0-9-]+\.[a-z]{2,}\b|\b[a-z0-9]+-[a-z0-9-]*(?:${BANK_ALT})[a-z0-9-]*\.[a-z]{2,}\b"""
        ),

        Rule(
            "Link points to a raw IP address", 35,
            """https?://\d{1,3}(?:\.\d{1,3}){3}"""
        ),

        Rule(
            "Shortened or chat-redirect link", 25,
            """\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|cutt\.ly|is\.gd|rb\.gy|shorturl\.at|tiny\.cc|ow\.ly|rebrand\.ly|t\.ly|s\.id|v\.gd|bl\.ink|lnkd\.in|wa\.me|t\.me)/\S+"""
        ),

        Rule(
            "Link on a high-abuse domain ending", 25,
            """\b[a-z0-9][a-z0-9-]{2,}\.(?:xyz|top|click|link|icu|buzz|cfd|sbs|rest|gq|tk|ml|cf|ga|vip|club|support|pw|monster|quest|cyou)\b"""
        ),

        Rule(
            "Urgent pressure language", 15,
            """\b(?:urgent(?:ly)?|immediate(?:ly)?|right now|asap|last (?:chance|warning|reminder|day)|final (?:notice|warning|reminder)|expir(?:es|ed|ing) (?:today|tonight|soon|in \d+)|within \d+ ?(?:hours?|hrs?|minutes?|mins?)|(?:act|update|verify|click|pay|call|login|respond|share) (?:now|today|immediately|fast)|limited time|today only|avoid (?:suspension|blocking|block|penalty|deactivation|disconnection|legal action))\b"""
        ),

        Rule(
            "Pushes you to tap a link or install an app", 12,
            """\b(?:click|tap|visit|open|log ?in|sign in|download|install)\b.{0,40}?(?:https?://|www\.|\b[a-z0-9-]+\.(?:com|in|net|org|co|xyz|top|link|app)\b|\blink\b|\bbelow\b)"""
        ),

        Rule(
            "Asks you to call or WhatsApp a number", 12,
            """\b(?:call|contact|whatsapp|text|message|reach)\b.{0,30}?\+?\d[\d\s-]{8,}\d"""
        )
    )

    /** Cyrillic / Greek look-alikes, zero-width characters and "fancy" maths-bold letters. */
    private val LOOKALIKE_CHARS = Regex("""[\u0370-\u03FF\u0400-\u04FF\u200B-\u200D\u2060\uFEFF\x{1D400}-\x{1D7FF}]""")

    private val BRAND_MENTION = Regex(
        """\b(?:sbi|state bank|hdfc|icici|axis bank|kotak|pnb|punjab national|bank of baroda|idfc|yes bank|paytm|phonepe|google pay|gpay|npci|rbi|upi|epfo|uidai|income tax|irctc|amazon|flipkart|jio|airtel|bsnl|fedex|dhl|bank)\b""",
        RegexOption.IGNORE_CASE
    )

    /** Phrases that make a keyword harmless ("do not share your OTP"). Removed before scanning. */
    private val SAFE_PHRASES: List<Regex> = listOf(
        Regex(
            """\b(?:do not|don\u0027?t|don\u2019?t|dont|never|not to|kindly do not|please do not|pls do not)\s+(?:share|disclose|give|tell|reveal|send|provide|forward)\b[^.!\n]{0,50}""",
            RegexOption.IGNORE_CASE
        ),
        Regex(
            """\b(?:will |would )?never\s+(?:ask|asks|call|calls|request|requests|message|messages)\b[^.!\n]{0,60}""",
            RegexOption.IGNORE_CASE
        ),
        Regex(
            """\b(?:successfully|been successfully)\s+(?:updated|verified|completed|activated|registered)\b""",
            RegexOption.IGNORE_CASE
        )
    )

    private val WHITESPACE = Regex("\\s+")

    // ------------------------------------------------------------------ call heuristics

    /** Country codes frequently reported in one-ring (Wangiri) and task-fraud call waves. Edit freely. */
    private val WANGIRI_PREFIXES = listOf(
        "+92", "+880", "+84", "+62", "+855", "+856", "+95", "+63",
        "+234", "+233", "+225", "+232", "+216", "+252"
    )

    private val REPEATED_DIGITS = Regex("([1-9])\\1{5,}")
    private val SEQUENTIAL_DIGITS = Regex("0123456|1234567|2345678|3456789|9876543|8765432|7654321|6543210")

    // ------------------------------------------------------------------ public API

    /** Scan an SMS (or any text message). [sender] is the originating address, if known. */
    fun analyzeMessage(sender: String?, body: String): ScamAnalysis {
        if (body.isBlank()) return ScamAnalysis(0, "Empty message", emptyList())

        val clipped = body.take(MAX_BODY_CHARS)
        val text = sanitize(clipped)
        val hits = ArrayList<Pair<String, Int>>()

        for (rule in messageRules) {
            if (rule.regex.containsMatchIn(text)) hits += rule.label to rule.weight
        }

        if (LOOKALIKE_CHARS.containsMatchIn(clipped)) {
            hits += "Look-alike or hidden characters" to 30
        }

        val senderId = sender.orEmpty().trim()
        if (senderId.isNotEmpty() && isPersonalNumber(senderId) && BRAND_MENTION.containsMatchIn(text)) {
            hits += "Bank or brand name sent from an ordinary mobile number" to 30
        }

        return finish(hits, "No scam indicators detected")
    }

    /**
     * Scan an incoming call from what Android exposes before the phone rings: the number,
     * whether caller ID is hidden, and (Android 11+) the carrier's STIR/SHAKEN verdict.
     */
    fun analyzeCall(
        number: String?,
        hiddenId: Boolean = false,
        verificationFailed: Boolean = false
    ): ScamAnalysis {
        val hits = ArrayList<Pair<String, Int>>()
        val raw = number.orEmpty().trim()
        val digits = raw.filter { it.isDigit() }

        if (verificationFailed) {
            hits += "Carrier caller-ID check failed (spoofed number)" to 55
        }

        if (hiddenId || digits.isEmpty()) {
            hits += "Hidden caller ID" to 30
        } else {
            val international =
                (raw.startsWith("+") && !raw.startsWith("+$HOME_COUNTRY_CODE")) || raw.startsWith("00")

            val e164 = when {
                raw.startsWith("+") -> "+$digits"
                raw.startsWith("00") -> "+" + digits.drop(2)
                else -> digits
            }

            val national = when {
                raw.startsWith("+$HOME_COUNTRY_CODE") -> digits.removePrefix(HOME_COUNTRY_CODE)
                digits.length == HOME_COUNTRY_CODE.length + 10 && digits.startsWith(HOME_COUNTRY_CODE) ->
                    digits.removePrefix(HOME_COUNTRY_CODE)
                raw.startsWith("0") && !raw.startsWith("00") -> digits.removePrefix("0")
                else -> digits
            }

            if (international) {
                hits += "Unknown international caller" to 35
                if (WANGIRI_PREFIXES.any { e164.startsWith(it) }) {
                    hits += "Country code often used in one-ring and task-fraud calls" to 20
                }
            }
            if (digits.length > 15) {
                hits += "Malformed number (likely spoofed)" to 40
            }
            if (REPEATED_DIGITS.containsMatchIn(national)) {
                hits += "Repeated-digit pattern (spoof signature)" to 40
            }
            if (SEQUENTIAL_DIGITS.containsMatchIn(national)) {
                hits += "Sequential-digit pattern (spoof signature)" to 35
            }
            if (national.startsWith("140") && national.length >= 10) {
                hits += "Telemarketing 140 series" to 30
            }
        }

        return finish(hits, "No spoofing signs in the caller number")
    }

    // ------------------------------------------------------------------ helpers

    private fun sanitize(body: String): String {
        var text = body.replace(WHITESPACE, " ").trim()
        for (phrase in SAFE_PHRASES) {
            text = phrase.replace(text, " ")
        }
        return text
    }

    private fun isPersonalNumber(sender: String): Boolean {
        val digitCount = sender.count { it.isDigit() }
        return digitCount >= 10 && sender.all { it.isDigit() || it == '+' || it == ' ' || it == '-' || it == '(' || it == ')' }
    }

    private fun finish(hits: List<Pair<String, Int>>, cleanText: String): ScamAnalysis {
        if (hits.isEmpty()) return ScamAnalysis(0, cleanText, emptyList())
        val ordered = hits.sortedByDescending { it.second }
        val score = ordered.sumOf { it.second }.coerceAtMost(MAX_SCORE)
        val labels = ordered.map { it.first }
        val extra = labels.size - 3
        val reason = labels.take(3).joinToString(" + ") + if (extra > 0) " + $extra more" else ""
        return ScamAnalysis(score, reason, labels)
    }
}
