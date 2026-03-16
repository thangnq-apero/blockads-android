package app.pwhs.blockads.ui.wireguard

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.outlined.CloudUpload
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Lan
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Router
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Timer
import androidx.compose.material.icons.outlined.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.pwhs.blockads.R
import app.pwhs.blockads.data.entities.WireGuardConfig
import app.pwhs.blockads.data.entities.WireGuardPeer
import org.koin.androidx.compose.koinViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WireGuardImportScreen(
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WireGuardImportViewModel = koinViewModel()
) {
    val config by viewModel.config.collectAsStateWithLifecycle()
    val isLoading by viewModel.isLoading.collectAsStateWithLifecycle()
    val error by viewModel.error.collectAsStateWithLifecycle()
    val isWgActive by viewModel.isWgActive.collectAsStateWithLifecycle()

    val snackbarHostState = remember { SnackbarHostState() }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { viewModel.importFromUri(it) }
    }

    // Collect one-shot events
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is WireGuardUiEvent.ConfigSaved -> {
                    snackbarHostState.showSnackbar("WireGuard config saved. Applying...")
                }
                is WireGuardUiEvent.ConfigCleared -> {
                    snackbarHostState.showSnackbar("WireGuard config cleared. Resetting...")
                }
            }
        }
    }

    // Show error via snackbar
    LaunchedEffect(error) {
        error?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.clearError()
        }
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.wireguard_import_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.accessibility_navigate_back)
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
        floatingActionButton = {
            if (!isWgActive) {
                ExtendedFloatingActionButton(
                    onClick = {
                        filePickerLauncher.launch(arrayOf("*/*"))
                    },
                    icon = {
                        Icon(
                            imageVector = Icons.Filled.FileOpen,
                            contentDescription = null
                        )
                    },
                    text = { Text(stringResource(R.string.wireguard_import_button)) },
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    contentColor = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
        }
    ) { padding ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Loading indicator
            AnimatedVisibility(
                visible = isLoading,
                enter = fadeIn(),
                exit = fadeOut(),
                modifier = Modifier.align(Alignment.Center)
            ) {
                CircularProgressIndicator()
            }

            // Content
            AnimatedVisibility(
                visible = !isLoading,
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                if (config != null) {
                    ConfigContent(
                        config = config!!,
                        isWgActive = isWgActive,
                        onSaveAndActivate = { viewModel.saveAndActivate() },
                        onClearWireGuard = { viewModel.clearWireGuard() },
                        modifier = Modifier.fillMaxSize()
                    )
                } else {
                    EmptyState(
                        modifier = Modifier.fillMaxSize()
                    )
                }
            }
        }
    }
}

// ── Empty State ──────────────────────────────────────────────────────────────

@Composable
private fun EmptyState(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier,
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = Icons.Outlined.CloudUpload,
            contentDescription = null,
            modifier = Modifier.size(80.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.wireguard_empty_title),
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = stringResource(R.string.wireguard_empty_desc),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
        )
    }
}

// ── Parsed Config Content ────────────────────────────────────────────────────

@Composable
private fun ConfigContent(
    config: WireGuardConfig,
    isWgActive: Boolean,
    onSaveAndActivate: () -> Unit,
    onClearWireGuard: () -> Unit,
    modifier: Modifier = Modifier
) {
    LazyColumn(
        modifier = modifier,
        contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Save & Activate / Clear WireGuard button
        item {
            if (isWgActive) {
                OutlinedButton(
                    onClick = onClearWireGuard,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Icon(
                        imageVector = Icons.Filled.Delete,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.wireguard_clear),
                        fontWeight = FontWeight.SemiBold
                    )
                }
            } else {
                Button(
                    onClick = onSaveAndActivate,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.primary
                    )
                ) {
                    Icon(
                        imageVector = Icons.Filled.SaveAlt,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        stringResource(R.string.wireguard_save_activate),
                        fontWeight = FontWeight.SemiBold
                    )
                }
            }

            // Active indicator
            if (isWgActive) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Center,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        text = stringResource(R.string.wireguard_active_label),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        }

        // Interface section
        item {
            InterfaceCard(config)
        }

        // Peer sections
        itemsIndexed(config.peers) { index, peer ->
            PeerCard(peer = peer, index = index)
        }

        // Bottom spacer for FAB clearance
        item { Spacer(modifier = Modifier.height(80.dp)) }
    }
}

// ── Interface Card ───────────────────────────────────────────────────────────

@Composable
private fun InterfaceCard(config: WireGuardConfig) {
    val iface = config.interfaceConfig
    var showPrivateKey by rememberSaveable { mutableStateOf(false) }
    @Suppress("DEPRECATION")
    val clipboardManager = LocalClipboardManager.current

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Outlined.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = stringResource(R.string.wireguard_section_interface),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Address
            ConfigRow(
                icon = Icons.Outlined.Lan,
                label = stringResource(R.string.wireguard_label_address),
                value = iface.address.joinToString(", ")
            )

            HorizontalDivider(
                modifier = Modifier.padding(vertical = 10.dp),
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
            )

            // Private Key (masked)
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Outlined.VpnKey,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.wireguard_label_private_key),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = if (showPrivateKey) iface.privateKey else "••••••••••••••••••••••••",
                        style = MaterialTheme.typography.bodyMedium.copy(
                            fontFamily = FontFamily.Monospace
                        ),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                IconButton(onClick = { showPrivateKey = !showPrivateKey }) {
                    Icon(
                        imageVector = if (showPrivateKey) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                        contentDescription = stringResource(R.string.wireguard_toggle_key_visibility),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(onClick = {
                    clipboardManager.setText(AnnotatedString(iface.privateKey))
                }) {
                    Icon(
                        imageVector = Icons.Filled.ContentCopy,
                        contentDescription = stringResource(R.string.wireguard_copy_key),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            // DNS
            if (iface.dns.isNotEmpty()) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 10.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                )
                ConfigRow(
                    icon = Icons.Outlined.Dns,
                    label = stringResource(R.string.wireguard_label_dns),
                    value = iface.dns.joinToString(", ")
                )
            }

            // Listen Port
            if (iface.listenPort != null) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 10.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                )
                ConfigRow(
                    icon = Icons.Outlined.Router,
                    label = stringResource(R.string.wireguard_label_listen_port),
                    value = iface.listenPort.toString()
                )
            }
        }
    }
}

// ── Peer Card ────────────────────────────────────────────────────────────────

@Composable
private fun PeerCard(peer: WireGuardPeer, index: Int) {
    var showPresharedKey by rememberSaveable { mutableStateOf(false) }
    @Suppress("DEPRECATION")
    val clipboardManager = LocalClipboardManager.current

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerLow
        )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = Icons.Outlined.Lock,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.tertiary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(10.dp))
                Text(
                    text = stringResource(R.string.wireguard_section_peer, index + 1),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.tertiary
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Public Key
            ConfigRow(
                icon = Icons.Outlined.VpnKey,
                label = stringResource(R.string.wireguard_label_public_key),
                value = peer.publicKey,
                monospace = true
            )

            // Endpoint
            if (peer.endpoint != null) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 10.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                )
                ConfigRow(
                    icon = Icons.Outlined.Router,
                    label = stringResource(R.string.wireguard_label_endpoint),
                    value = peer.endpoint
                )
            }

            // Allowed IPs
            if (peer.allowedIPs.isNotEmpty()) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 10.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                )
                ConfigRow(
                    icon = Icons.Outlined.Lan,
                    label = stringResource(R.string.wireguard_label_allowed_ips),
                    value = peer.allowedIPs.joinToString(", ")
                )
            }

            // Preshared Key
            if (peer.presharedKey != null) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 10.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Outlined.Lock,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.wireguard_label_preshared_key),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = if (showPresharedKey) peer.presharedKey else "••••••••••••••••••••••••",
                            style = MaterialTheme.typography.bodyMedium.copy(
                                fontFamily = FontFamily.Monospace
                            ),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    IconButton(onClick = { showPresharedKey = !showPresharedKey }) {
                        Icon(
                            imageVector = if (showPresharedKey) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                            contentDescription = stringResource(R.string.wireguard_toggle_key_visibility),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = {
                        clipboardManager.setText(AnnotatedString(peer.presharedKey))
                    }) {
                        Icon(
                            imageVector = Icons.Filled.ContentCopy,
                            contentDescription = stringResource(R.string.wireguard_copy_key),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            // Persistent Keepalive
            if (peer.persistentKeepalive != null) {
                HorizontalDivider(
                    modifier = Modifier.padding(vertical = 10.dp),
                    color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
                )
                ConfigRow(
                    icon = Icons.Outlined.Timer,
                    label = stringResource(R.string.wireguard_label_keepalive),
                    value = stringResource(R.string.wireguard_keepalive_value, peer.persistentKeepalive)
                )
            }
        }
    }
}

// ── Reusable Row ─────────────────────────────────────────────────────────────

@Composable
private fun ConfigRow(
    icon: ImageVector,
    label: String,
    value: String,
    monospace: Boolean = false
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(10.dp))
        Column {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value,
                style = if (monospace) {
                    MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace)
                } else {
                    MaterialTheme.typography.bodyMedium
                },
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}
