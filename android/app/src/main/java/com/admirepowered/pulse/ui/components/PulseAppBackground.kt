package com.admirepowered.pulse.ui.components

import android.graphics.BitmapFactory
import android.net.Uri
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.blur
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@Composable
fun PulseAppBackground(
    backgroundUri: String,
    backgroundOpacityPercent: Int,
    backgroundBlurDp: Int,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val image = produceState<ImageBitmap?>(initialValue = null, backgroundUri) {
        value = if (backgroundUri.isBlank()) {
            null
        } else {
            withContext(Dispatchers.IO) {
                runCatching {
                    val file = File(backgroundUri)
                    val bitmap = if (file.exists() && file.isFile) {
                        file.inputStream().use(BitmapFactory::decodeStream)
                    } else {
                        context.contentResolver.openInputStream(Uri.parse(backgroundUri))?.use(BitmapFactory::decodeStream)
                    }
                    bitmap?.asImageBitmap()
                }.getOrNull()
            }
        }
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background),
    ) {
        image.value?.let { bitmap ->
            val imageAlpha = (backgroundOpacityPercent.coerceIn(0, 60).toFloat() / 100f)
            val overlayAlpha = (0.98f - imageAlpha * 0.7f).coerceIn(0.56f, 0.98f)
            Image(
                bitmap = bitmap,
                contentDescription = null,
                contentScale = ContentScale.Crop,
                modifier = Modifier
                    .fillMaxSize()
                    .blur(backgroundBlurDp.coerceIn(0, 40).dp)
                    .alpha(imageAlpha),
            )
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.background.copy(alpha = overlayAlpha)),
            )
        }
        content()
    }
}
