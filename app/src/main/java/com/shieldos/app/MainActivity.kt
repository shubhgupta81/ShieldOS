package com.shieldos.app

import android.Manifest
import android.app.role.RoleManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateIntAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Phone
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

// ---------------------------------------------------------------------------------------------
// Design tokens: iOS 18 dark mode
// ---------------------------------------------------------------------------------------------

private object Palette {
    val Black = Color(0xFF000000)
    val Card = Color(0xFF1C1C1E)
    val Blue = Color(0xFF0071E3)
    val Green = Color(0xFF34C759)
    val Red = Color(0xFFFF3B30)
    val Orange = Color(0xFFFF9F0A)
    val Secondary = Color(0xFF8E8E93)
    val Tertiary = Color(0xFF636366)
    val Hairline = Color(0x1AFFFFFF)
    val Separator = Color(0x29FFFFFF)
}

class MainActivity : ComponentActivity() {

    // Bumped on every resume so permission state is re-read after returning from system screens.
    private val resumeTick = mutableIntStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        ThreatStore.load(applicationContext)
        AlertNotificationHelper.ensureChannel(applicationContext)

        setContent {
            ShieldOSTheme {
                ShieldOSApp(resumeTick.intValue)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        resumeTick.intValue = resumeTick.intValue + 1
    }
}

@Composable
private fun ShieldOSTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Palette.Blue,
            onPrimary = Color.White,
            background = Palette.Black,
            onBackground = Color.White,
            surface = Palette.Card,
            onSurface = Color.White,
            error = Palette.Red
        ),
        content = content
    )
}

// ---------------------------------------------------------------------------------------------
// Permission and role state
// ---------------------------------------------------------------------------------------------

private data class Protection(
    val sms: Boolean,
    val phone: Boolean,
    val notifications: Boolean,
    val screening: Boolean,
    val screeningSupported: Boolean
) {
    val callShield: Boolean get() = screening || !screeningSupported
    val activeShields: Int get() = listOf(sms, callShield, notifications).count { it }
    val allGranted: Boolean get() = activeShields == 3
}

private fun readProtection(context: Context): Protection {
    val enabledListeners = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners").orEmpty()
    val notifListenerActive = enabledListeners.contains(context.packageName)

    val screeningSupported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
    val screeningHeld = screeningSupported &&
        context.getSystemService(RoleManager::class.java)?.isRoleHeld(RoleManager.ROLE_CALL_SCREENING) == true

    return Protection(
        sms = notifListenerActive,
        phone = screeningHeld,
        notifications = NotificationManagerCompat.from(context).areNotificationsEnabled(),
        screening = screeningHeld,
        screeningSupported = screeningSupported
    )
}

/** Intent for the system "make ShieldOS your call screening app" dialog, or null if not needed. */
private fun roleIntent(context: Context): Intent? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
    val manager = context.getSystemService(RoleManager::class.java) ?: return null
    if (!manager.isRoleAvailable(RoleManager.ROLE_CALL_SCREENING)) return null
    if (manager.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)) return null
    return manager.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING)
}

// ---------------------------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------------------------

@Composable
private fun ShieldOSApp(resumeTick: Int) {
    val context = LocalContext.current
    var localTick by remember { mutableIntStateOf(0) }
    val protection = remember(resumeTick, localTick) { readProtection(context) }

    val events by ThreatStore.events.collectAsState()
    val scanned by ThreatStore.scanned.collectAsState()
    val flagged by ThreatStore.flagged.collectAsState()

    val roleLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { localTick++ }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        localTick++
        val intent = roleIntent(context)
        if (intent != null) roleLauncher.launch(intent)
    }

    fun requestEverything() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && !protection.notifications) {
            permissionLauncher.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS))
            return
        }
        val intent = roleIntent(context)
        if (intent != null && !protection.screening) {
            roleLauncher.launch(intent)
            return
        }
        if (!protection.sms) {
            context.startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        }
    }

    fun openAppInfo() {
        val intent = Intent(
            Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
            Uri.fromParts("package", context.packageName, null)
        ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }

    fun hintIfNotificationsOff() {
        if (!NotificationManagerCompat.from(context).areNotificationsEnabled()) {
            Toast.makeText(
                context,
                "The threat was added to the feed. Turn on notifications to see the warning banner too.",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Palette.Black,
        contentColor = Color.White
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .systemBarsPadding(),
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, top = 12.dp, bottom = 32.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item(key = "header") { Header() }

            item(key = "hero") { HeroCard(protection, scanned, flagged) }

            item(key = "permissions") {
                PermissionCard(
                    protection = protection,
                    onGrant = { requestEverything() },
                    onOpenSettings = { openAppInfo() }
                )
            }

            item(key = "simulator") {
                SimulatorCard(
                    onCall = {
                        val call = DemoScenarios.nextCall()
                        ThreatPipeline.handleCall(
                            context, call.number, call.hidden, call.verificationFailed, simulated = true
                        )
                        hintIfNotificationsOff()
                    },
                    onSms = {
                        val sms = DemoScenarios.nextSms()
                        ThreatPipeline.handleSms(context, sms.sender, sms.body, simulated = true)
                        hintIfNotificationsOff()
                    }
                )
            }

            item(key = "feed-header") {
                FeedHeader(count = events.size, onClear = { ThreatStore.clear(context) })
            }

            if (events.isEmpty()) {
                item(key = "feed-empty") { EmptyFeed() }
            } else {
                items(events, key = { it.id }) { event -> ThreatRow(event) }
            }

            item(key = "footer") {
                Text(
                    "Everything runs on your phone. Nothing is uploaded.",
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    fontSize = 13.sp,
                    color = Palette.Tertiary,
                    textAlign = TextAlign.Center
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Building blocks
// ---------------------------------------------------------------------------------------------

@Composable
private fun AppleCard(
    modifier: Modifier = Modifier,
    corner: Int = 24,
    padding: Int = 20,
    content: @Composable ColumnScope.() -> Unit
) {
    val shape = RoundedCornerShape(corner.dp)
    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(shape)
            .background(Palette.Card)
            .background(Brush.verticalGradient(listOf(Color(0x14FFFFFF), Color(0x00FFFFFF))))
            .border(1.dp, Palette.Hairline, shape)
            .padding(padding.dp),
        content = content
    )
}

@Composable
private fun ActionButton(text: String, color: Color, icon: ImageVector?, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier
            .fillMaxWidth()
            .height(54.dp),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(containerColor = color, contentColor = Color.White)
    ) {
        if (icon != null) {
            Icon(icon, null, Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
        }
        Text(text, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun Header() {
    Column(modifier = Modifier.padding(top = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                painter = painterResource(R.drawable.ic_shield),
                contentDescription = null,
                tint = Palette.Blue,
                modifier = Modifier.size(32.dp)
            )
            Spacer(Modifier.width(10.dp))
            Text("ShieldOS", fontSize = 34.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.8).sp)
        }
        Spacer(Modifier.height(4.dp))
        Text("Scam protection for calls and texts", fontSize = 15.sp, color = Palette.Secondary)
    }
}

@Composable
private fun HeroCard(protection: Protection, scanned: Int, flagged: Int) {
    val active = protection.activeShields
    val statusColor = when (active) {
        3 -> Palette.Green
        0 -> Palette.Red
        else -> Palette.Orange
    }
    val headline = when (active) {
        3 -> "You’re protected"
        0 -> "Not protected"
        else -> "Almost there"
    }
    val caption = when (active) {
        3 -> "ShieldOS is checking every incoming call and SMS on this phone."
        0 -> "Grant the permissions below to switch protection on."
        else -> "Finish setup to turn on all three shields."
    }
    val statusLabel = if (active == 3) "Live protection" else "Setup needed"

    val pulse = rememberInfiniteTransition(label = "pulse")
    val dotAlpha by pulse.animateFloat(
        initialValue = 0.35f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(1100, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "dot"
    )
    val scannedShown by animateIntAsState(scanned, label = "scanned")
    val flaggedShown by animateIntAsState(flagged, label = "flagged")

    val shape = RoundedCornerShape(28.dp)
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(Palette.Card)
            .drawBehind {
                val glowCenter = Offset(size.width * 0.92f, 0f)
                drawCircle(
                    brush = Brush.radialGradient(
                        colors = listOf(statusColor.copy(alpha = 0.30f), Color.Transparent),
                        center = glowCenter,
                        radius = size.width * 0.75f
                    ),
                    radius = size.width * 0.75f,
                    center = glowCenter
                )
            }
            .border(1.dp, Palette.Hairline, shape)
            .padding(24.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(9.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = dotAlpha))
            )
            Spacer(Modifier.width(8.dp))
            Text(
                statusLabel,
                modifier = Modifier.weight(1f),
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold,
                color = statusColor
            )
            Box(
                modifier = Modifier
                    .size(46.dp)
                    .clip(CircleShape)
                    .background(statusColor.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    painter = painterResource(R.drawable.ic_shield),
                    contentDescription = null,
                    tint = statusColor,
                    modifier = Modifier.size(26.dp)
                )
            }
        }

        Spacer(Modifier.height(18.dp))
        Text(headline, fontSize = 38.sp, lineHeight = 42.sp, fontWeight = FontWeight.Bold, letterSpacing = (-1).sp)
        Spacer(Modifier.height(6.dp))
        Text(caption, fontSize = 16.sp, color = Palette.Secondary)

        Spacer(Modifier.height(22.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(1.dp)
                .background(Palette.Separator)
        )
        Spacer(Modifier.height(18.dp))

        Row(modifier = Modifier.fillMaxWidth()) {
            Stat("Checked", scannedShown.toString(), Modifier.weight(1f))
            Stat(
                "Threats flagged",
                flaggedShown.toString(),
                Modifier.weight(1f),
                if (flagged > 0) Palette.Red else Color.White
            )
            Stat("Shields on", "$active of 3", Modifier.weight(1f), statusColor)
        }
    }
}

@Composable
private fun Stat(label: String, value: String, modifier: Modifier = Modifier, valueColor: Color = Color.White) {
    Column(modifier = modifier) {
        Text(value, fontSize = 28.sp, fontWeight = FontWeight.SemiBold, color = valueColor, letterSpacing = (-0.5).sp)
        Spacer(Modifier.height(2.dp))
        Text(label, fontSize = 12.sp, color = Palette.Secondary)
    }
}

@Composable
private fun PermissionCard(protection: Protection, onGrant: () -> Unit, onOpenSettings: () -> Unit) {
    AppleCard {
        Text(
            if (protection.allGranted) "Everything is switched on" else "One tap to switch on protection",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
            letterSpacing = (-0.4).sp
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "ShieldOS needs these to see your calls and texts. Nothing ever leaves your phone.",
            fontSize = 14.sp,
            color = Palette.Secondary
        )
        Spacer(Modifier.height(12.dp))

        PermissionRow(Icons.Filled.Email, "Message scanner", "Scan SMS, WhatsApp & Telegram", protection.sms)
        PermissionRow(Icons.Filled.Phone, "Phone and call log", "Know who is calling you", protection.phone)
        PermissionRow(
            Icons.Filled.Notifications,
            "Notifications",
            "Show instant scam warning banners",
            protection.notifications
        )
        PermissionRow(
            Icons.Filled.Lock,
            "Call screening",
            if (protection.screeningSupported) "Let ShieldOS screen incoming calls" else "Needs Android 10 or newer",
            protection.screening,
            available = protection.screeningSupported
        )

        Spacer(Modifier.height(14.dp))
        if (!protection.allGranted) {
            ActionButton("Grant All Permissions", Palette.Blue, null, onGrant)
            TextButton(
                onClick = onOpenSettings,
                modifier = Modifier.align(Alignment.CenterHorizontally)
            ) {
                Text(
                    "Installed from GitHub? Allow restricted settings",
                    fontSize = 14.sp,
                    color = Palette.Blue,
                    textAlign = TextAlign.Center
                )
            }
        } else {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(Palette.Green.copy(alpha = 0.14f))
                    .padding(14.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Filled.CheckCircle, null, Modifier.size(22.dp), tint = Palette.Green)
                Spacer(Modifier.width(10.dp))
                Text("All permissions granted", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = Palette.Green)
            }
        }
    }
}

@Composable
private fun PermissionRow(
    icon: ImageVector,
    title: String,
    subtitle: String,
    granted: Boolean,
    available: Boolean = true
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(38.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(Palette.Blue.copy(alpha = 0.18f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, null, Modifier.size(20.dp), tint = Palette.Blue)
        }
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Text(subtitle, fontSize = 13.sp, color = Palette.Secondary)
        }
        Spacer(Modifier.width(8.dp))
        when {
            !available -> Text("Unavailable", fontSize = 12.sp, color = Palette.Tertiary)
            granted -> Icon(Icons.Filled.CheckCircle, null, Modifier.size(26.dp), tint = Palette.Green)
            else -> Box(
                modifier = Modifier
                    .size(24.dp)
                    .border(2.dp, Palette.Tertiary, CircleShape)
            )
        }
    }
}

@Composable
private fun SimulatorCard(onCall: () -> Unit, onSms: () -> Unit) {
    AppleCard {
        Text("Try it live", fontSize = 22.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.4).sp)
        Spacer(Modifier.height(4.dp))
        Text(
            "Runs the real detection engine and raises a real Android warning banner. Each tap plays a different scam.",
            fontSize = 14.sp,
            color = Palette.Secondary
        )
        Spacer(Modifier.height(16.dp))
        ActionButton("Simulate Incoming Scam Call", Palette.Red, Icons.Filled.Phone, onCall)
        Spacer(Modifier.height(10.dp))
        ActionButton("Simulate Phishing SMS", Palette.Blue, Icons.Filled.Email, onSms)
    }
}

@Composable
private fun FeedHeader(count: Int, onClear: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text("Recent threats", fontSize = 22.sp, fontWeight = FontWeight.Bold, letterSpacing = (-0.4).sp)
            Text(
                if (count == 0) "Nothing flagged yet" else "$count flagged",
                fontSize = 13.sp,
                color = Palette.Secondary
            )
        }
        if (count > 0) {
            TextButton(onClick = onClear) {
                Text("Clear", fontSize = 15.sp, color = Palette.Blue)
            }
        }
    }
}

@Composable
private fun EmptyFeed() {
    AppleCard {
        Column(
            modifier = Modifier.fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                painter = painterResource(R.drawable.ic_shield),
                contentDescription = null,
                tint = Palette.Green,
                modifier = Modifier.size(40.dp)
            )
            Spacer(Modifier.height(10.dp))
            Text("All clear", fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(
                "Flagged calls and texts show up here the moment they arrive. Tap a demo button above to see one.",
                fontSize = 14.sp,
                color = Palette.Secondary,
                textAlign = TextAlign.Center
            )
        }
    }
}

@Composable
private fun ThreatRow(event: ThreatEvent) {
    val tint = if (event.level == RiskLevel.DANGEROUS) Palette.Red else Palette.Orange

    AppleCard(corner = 20, padding = 16) {
        Row(verticalAlignment = Alignment.Top) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .clip(CircleShape)
                    .background(tint.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    if (event.source == ThreatSource.CALL) Icons.Filled.Phone else Icons.Filled.Email,
                    null,
                    Modifier.size(22.dp),
                    tint = tint
                )
            }
            Spacer(Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        event.origin,
                        modifier = Modifier.weight(1f),
                        fontSize = 16.sp,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                    Spacer(Modifier.width(8.dp))
                    RiskBadge(event.riskScore, event.level)
                }
                Spacer(Modifier.height(4.dp))
                Text(
                    event.preview,
                    fontSize = 14.sp,
                    color = Palette.Secondary,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(Modifier.height(10.dp))
                RiskBar(event.riskScore, tint)
                Spacer(Modifier.height(8.dp))
                Row(verticalAlignment = Alignment.Top) {
                    Icon(
                        Icons.Filled.Warning,
                        null,
                        Modifier
                            .padding(top = 1.dp)
                            .size(14.dp),
                        tint = tint
                    )
                    Spacer(Modifier.width(6.dp))
                    Text(event.reason, fontSize = 13.sp, color = tint, maxLines = 3, overflow = TextOverflow.Ellipsis)
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    if (event.simulated) "${timeLabel(event.timestamp)}, demo" else timeLabel(event.timestamp),
                    fontSize = 12.sp,
                    color = Palette.Tertiary
                )
            }
        }
    }
}

@Composable
private fun RiskBadge(score: Int, level: RiskLevel) {
    val color = if (level == RiskLevel.DANGEROUS) Palette.Red else Palette.Orange
    val label = if (level == RiskLevel.DANGEROUS) "$score% high risk" else "$score% suspicious"
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(color.copy(alpha = 0.18f))
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Text(label, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = color, maxLines = 1)
    }
}

@Composable
private fun RiskBar(score: Int, color: Color) {
    val fraction = score.coerceIn(0, 100) / 100f
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(5.dp)
            .clip(RoundedCornerShape(50))
            .background(Palette.Separator)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth(fraction)
                .height(5.dp)
                .background(color)
        )
    }
}

private fun timeLabel(timestamp: Long): String {
    val now = System.currentTimeMillis()
    return if (now - timestamp < DateUtils.MINUTE_IN_MILLIS) {
        "Just now"
    } else {
        DateUtils.getRelativeTimeSpanString(timestamp, now, DateUtils.MINUTE_IN_MILLIS).toString()
    }
}
