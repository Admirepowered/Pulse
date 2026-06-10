package com.admirepowered.pulse.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.admirepowered.pulse.ui.ThemeMode

private val LightColors = lightColorScheme(
    primary = Color(0xFF006B5F),
    onPrimary = Color.White,
    primaryContainer = Color(0xFF74F8DF),
    onPrimaryContainer = Color(0xFF00201C),
    secondary = Color(0xFF4A635E),
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFCDE8E1),
    onSecondaryContainer = Color(0xFF05201B),
    tertiary = Color(0xFF456179),
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFCBE6FF),
    onTertiaryContainer = Color(0xFF001E31),
    background = Color(0xFFF7FBF8),
    onBackground = Color(0xFF181D1B),
    surface = Color(0xFFF7FBF8),
    onSurface = Color(0xFF181D1B),
    onSurfaceVariant = Color(0xFF3F4946),
    surfaceContainer = Color(0xFFECEFEB),
    surfaceContainerHigh = Color(0xFFE4E8E4),
    outline = Color(0xFF6F7975),
    outlineVariant = Color(0xFFBFC9C5),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF53DBC5),
    onPrimary = Color(0xFF003731),
    primaryContainer = Color(0xFF005047),
    onPrimaryContainer = Color(0xFF74F8DF),
    secondary = Color(0xFFB1CCC5),
    onSecondary = Color(0xFF1C3530),
    secondaryContainer = Color(0xFF334B46),
    onSecondaryContainer = Color(0xFFCDE8E1),
    tertiary = Color(0xFFADCBE6),
    onTertiary = Color(0xFF153349),
    tertiaryContainer = Color(0xFF2D4960),
    onTertiaryContainer = Color(0xFFCBE6FF),
    background = Color(0xFF101412),
    onBackground = Color(0xFFE8F0EC),
    surface = Color(0xFF101412),
    onSurface = Color(0xFFE8F0EC),
    onSurfaceVariant = Color(0xFFC2CBC7),
    surfaceContainer = Color(0xFF1C211F),
    surfaceContainerHigh = Color(0xFF272B29),
    outline = Color(0xFF8C9692),
    outlineVariant = Color(0xFF3F4946),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6),
)

@Composable
fun PulseTheme(
    themeMode: ThemeMode,
    content: @Composable () -> Unit,
) {
    val darkTheme = when (themeMode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Light -> false
        ThemeMode.Dark -> true
    }
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
