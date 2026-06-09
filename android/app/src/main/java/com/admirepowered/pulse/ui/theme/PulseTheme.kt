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
    tertiary = Color(0xFF456179),
    background = Color(0xFFF7FBF8),
    surface = Color(0xFFF7FBF8),
    surfaceContainer = Color(0xFFECEFEB),
    surfaceContainerHigh = Color(0xFFE4E8E4),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFF53DBC5),
    onPrimary = Color(0xFF003731),
    primaryContainer = Color(0xFF005047),
    onPrimaryContainer = Color(0xFF74F8DF),
    secondary = Color(0xFFB1CCC5),
    tertiary = Color(0xFFADCBE6),
    background = Color(0xFF101412),
    surface = Color(0xFF101412),
    surfaceContainer = Color(0xFF1C211F),
    surfaceContainerHigh = Color(0xFF272B29),
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
