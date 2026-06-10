package com.admirepowered.pulse.ui.screens

import android.widget.Toast
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Redo
import androidx.compose.material.icons.automirrored.filled.Undo
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AssistChip
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

@Composable
fun ProfileEditorScreen(
    title: String,
    content: String,
    loading: Boolean,
    saving: Boolean,
    message: String,
    onContentChange: (String) -> Unit,
    onSave: () -> Unit,
    onShare: (String) -> Unit,
    onExportFile: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var searchQuery by remember { mutableStateOf("") }
    var searchIndex by remember { mutableStateOf(0) }
    var jumpLineText by remember { mutableStateOf("") }
    var editorValue by remember {
        mutableStateOf(TextFieldValue(content, selection = TextRange(content.length)))
    }
    var undoStack by remember { mutableStateOf<List<TextFieldValue>>(emptyList()) }
    var redoStack by remember { mutableStateOf<List<TextFieldValue>>(emptyList()) }
    LaunchedEffect(content) {
        if (content != editorValue.text) {
            editorValue = TextFieldValue(content, selection = TextRange(content.length))
            undoStack = emptyList()
            redoStack = emptyList()
        }
    }
    val editorText = editorValue.text
    val cursorStatus = remember(editorText, editorValue.selection) {
        editorText.editorCursorStatus(editorValue.selection.start)
    }
    val searchMatches = remember(editorText, searchQuery) {
        editorText.searchMatches(searchQuery)
    }
    LaunchedEffect(searchMatches) {
        searchIndex = if (searchMatches.isEmpty()) 0 else searchIndex.coerceIn(0, searchMatches.lastIndex)
    }
    val yamlHighlight = rememberYamlHighlightTransformation(
        searchMatches = searchMatches,
        activeSearchIndex = searchIndex,
    )
    fun applyEditorValue(updated: TextFieldValue) {
        if (updated == editorValue) return
        if (updated.text != editorValue.text) {
            undoStack = (undoStack + editorValue).takeLast(80)
            redoStack = emptyList()
        }
        editorValue = updated
        onContentChange(updated.text)
    }
    fun undoEdit() {
        val previous = undoStack.lastOrNull() ?: return
        undoStack = undoStack.dropLast(1)
        redoStack = (redoStack + editorValue).takeLast(80)
        editorValue = previous
        onContentChange(previous.text)
    }
    fun redoEdit() {
        val next = redoStack.lastOrNull() ?: return
        redoStack = redoStack.dropLast(1)
        undoStack = (undoStack + editorValue).takeLast(80)
        editorValue = next
        onContentChange(next.text)
    }
    fun insertSnippet(snippet: String) {
        val updated = editorValue.insertYamlSnippet(snippet)
        applyEditorValue(updated)
    }
    fun applyEditorAction(action: (TextFieldValue) -> TextFieldValue) {
        val updated = action(editorValue)
        applyEditorValue(updated)
    }
    fun jumpSearch(delta: Int) {
        if (searchMatches.isEmpty()) return
        val nextIndex = Math.floorMod(searchIndex + delta, searchMatches.size)
        searchIndex = nextIndex
        val range = searchMatches[nextIndex]
        editorValue = editorValue.copy(selection = TextRange(range.first, range.last))
    }
    fun jumpToLine() {
        val requestedLine = jumpLineText.toIntOrNull() ?: return
        val offset = editorText.offsetForLine(requestedLine)
        editorValue = editorValue.copy(selection = TextRange(offset))
    }
    val diagnostics = remember(editorText) { editorText.yamlDiagnostics() }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Row(
                modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回订阅")
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text("编辑配置", style = MaterialTheme.typography.headlineSmall)
                    Text(
                        title.ifBlank { "Profile" },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                }
                if (saving) {
                    CircularProgressIndicator(strokeWidth = 2.dp)
                } else {
                    IconButton(
                        onClick = {
                            clipboard.setText(AnnotatedString(editorText))
                            Toast.makeText(context, "配置已复制", Toast.LENGTH_SHORT).show()
                        },
                        enabled = !loading && editorText.isNotBlank(),
                    ) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "复制配置")
                    }
                    IconButton(
                        onClick = { onShare(editorText) },
                        enabled = !loading && editorText.isNotBlank(),
                    ) {
                        Icon(Icons.Filled.Share, contentDescription = "分享配置")
                    }
                    IconButton(
                        onClick = { onExportFile(editorText) },
                        enabled = !loading && editorText.isNotBlank(),
                    ) {
                        Icon(Icons.Filled.Download, contentDescription = "导出当前配置")
                    }
                    IconButton(
                        onClick = { undoEdit() },
                        enabled = !loading && undoStack.isNotEmpty(),
                    ) {
                        Icon(Icons.AutoMirrored.Filled.Undo, contentDescription = "撤销")
                    }
                    IconButton(
                        onClick = { redoEdit() },
                        enabled = !loading && redoStack.isNotEmpty(),
                    ) {
                        Icon(Icons.AutoMirrored.Filled.Redo, contentDescription = "重做")
                    }
                    IconButton(
                        onClick = onSave,
                        enabled = !loading && editorText.isNotBlank(),
                    ) {
                        Icon(Icons.Filled.Save, contentDescription = "保存配置")
                    }
                }
            }
        }
        if (message.isNotBlank()) {
            item {
                Text(
                    message,
                    modifier = Modifier.padding(horizontal = 20.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
        if (!loading && diagnostics.isNotEmpty()) {
            item {
                Column(
                    modifier = Modifier.padding(horizontal = 20.dp),
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(
                        "基础检查发现 ${diagnostics.size} 个提示",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.error,
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        AssistChip(
                            onClick = {
                                clipboard.setText(AnnotatedString(diagnostics.toDiagnosticsText(title)))
                            },
                            label = { Text("复制诊断") },
                        )
                        AssistChip(
                            onClick = { onShare(diagnostics.toDiagnosticsText(title)) },
                            label = { Text("分享诊断") },
                        )
                    }
                    diagnostics.take(5).forEach { diagnostic ->
                        Text(
                            diagnostic,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                    if (diagnostics.size > 5) {
                        Text(
                            "还有 ${diagnostics.size - 5} 个提示未显示",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.secondary,
                        )
                    }
                }
            }
        }
        if (!loading) {
            item {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = {
                            searchQuery = it
                            searchIndex = 0
                        },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        label = { Text("搜索配置") },
                        leadingIcon = {
                            Icon(Icons.Filled.Search, contentDescription = null)
                        },
                        trailingIcon = {
                            if (searchQuery.isNotBlank()) {
                                IconButton(
                                    onClick = {
                                        searchQuery = ""
                                        searchIndex = 0
                                    },
                                ) {
                                    Icon(Icons.Filled.Close, contentDescription = "清空搜索")
                                }
                            }
                        },
                        supportingText = {
                            val tip = when {
                                searchQuery.isBlank() -> "输入关键词后会高亮匹配项"
                                searchMatches.isEmpty() -> "没有匹配项"
                                else -> "${searchIndex + 1}/${searchMatches.size}"
                            }
                            Text(tip)
                        },
                    )
                    IconButton(
                        onClick = { jumpSearch(-1) },
                        enabled = searchMatches.isNotEmpty(),
                    ) {
                        Icon(Icons.Filled.KeyboardArrowUp, contentDescription = "上一个匹配")
                    }
                    IconButton(
                        onClick = { jumpSearch(1) },
                        enabled = searchMatches.isNotEmpty(),
                    ) {
                        Icon(Icons.Filled.KeyboardArrowDown, contentDescription = "下一个匹配")
                    }
                }
            }
        }
        if (!loading) {
            item {
                Column(
                    modifier = Modifier.padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "常用片段",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        yamlSnippets.forEach { snippet ->
                            AssistChip(
                                onClick = { insertSnippet(snippet.text) },
                                label = { Text(snippet.label) },
                            )
                        }
                    }
                }
            }
            item {
                Row(
                    modifier = Modifier
                        .padding(horizontal = 12.dp)
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    AssistChip(onClick = { }, label = { Text("行 ${cursorStatus.line}") })
                    AssistChip(onClick = { }, label = { Text("列 ${cursorStatus.column}") })
                    AssistChip(onClick = { }, label = { Text("${cursorStatus.totalLines} 行") })
                    AssistChip(onClick = { }, label = { Text("${cursorStatus.characters} 字符") })
                    AssistChip(
                        onClick = {
                            clipboard.setText(AnnotatedString(editorText.currentYamlLine(editorValue.selection.start)))
                            Toast.makeText(context, "当前行已复制", Toast.LENGTH_SHORT).show()
                        },
                        enabled = editorText.isNotEmpty(),
                        label = { Text("复制当前行") },
                    )
                }
            }
            item {
                Row(
                    modifier = Modifier.padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    OutlinedTextField(
                        value = jumpLineText,
                        onValueChange = { value ->
                            jumpLineText = value.filter(Char::isDigit).take(6)
                        },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        label = { Text("跳转到行") },
                        placeholder = { Text("1 - ${cursorStatus.totalLines}") },
                    )
                    AssistChip(
                        onClick = { jumpToLine() },
                        enabled = jumpLineText.toIntOrNull() != null,
                        label = { Text("跳转") },
                    )
                }
            }
            item {
                Column(
                    modifier = Modifier.padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "编辑辅助",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        AssistChip(
                            onClick = { applyEditorAction { it.indentSelectedYamlLines() } },
                            label = { Text("缩进") },
                        )
                        AssistChip(
                            onClick = { applyEditorAction { it.outdentSelectedYamlLines() } },
                            label = { Text("反缩进") },
                        )
                        AssistChip(
                            onClick = { applyEditorAction { it.toggleYamlComment() } },
                            label = { Text("注释切换") },
                        )
                        AssistChip(
                            onClick = { applyEditorAction { it.cleanYamlWhitespace() } },
                            label = { Text("清理空白") },
                        )
                    }
                }
            }
            item {
                Column(
                    modifier = Modifier.padding(horizontal = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "关键词补全",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.secondary,
                    )
                    Row(
                        modifier = Modifier.horizontalScroll(rememberScrollState()),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        yamlCompletions.forEach { completion ->
                            AssistChip(
                                onClick = { insertSnippet(completion.text) },
                                label = { Text(completion.label) },
                            )
                        }
                    }
                }
            }
        }
        item {
            if (loading) {
                CircularProgressIndicator(modifier = Modifier.padding(horizontal = 20.dp))
            } else {
                OutlinedTextField(
                    value = editorValue,
                    onValueChange = {
                        applyEditorValue(it)
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 520.dp)
                        .padding(horizontal = 12.dp),
                    textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                    label = { Text("YAML") },
                    visualTransformation = yamlHighlight,
                    minLines = 24,
                )
            }
        }
    }
}

private data class YamlSnippet(
    val label: String,
    val text: String,
)

private data class EditorCursorStatus(
    val line: Int,
    val column: Int,
    val totalLines: Int,
    val characters: Int,
)

private fun List<String>.toDiagnosticsText(title: String): String {
    return buildString {
        appendLine("Pulse Android YAML 诊断")
        appendLine("配置: ${title.ifBlank { "Profile" }}")
        appendLine("提示数: $size")
        forEachIndexed { index, item ->
            appendLine("${index + 1}. $item")
        }
    }.trimEnd()
}

private fun String.editorCursorStatus(selectionStart: Int): EditorCursorStatus {
    val cursor = selectionStart.coerceIn(0, length)
    var line = 1
    var lineStart = 0
    for (index in 0 until cursor) {
        if (this[index] == '\n') {
            line += 1
            lineStart = index + 1
        }
    }
    val totalLines = if (isEmpty()) 1 else count { it == '\n' } + 1
    return EditorCursorStatus(
        line = line,
        column = cursor - lineStart + 1,
        totalLines = totalLines,
        characters = length,
    )
}

private fun String.offsetForLine(line: Int): Int {
    val targetLine = line.coerceAtLeast(1)
    var currentLine = 1
    indices.forEach { index ->
        if (currentLine == targetLine) return index
        if (this[index] == '\n') currentLine += 1
    }
    return length
}

private fun String.currentYamlLine(selectionStart: Int): String {
    if (isEmpty()) return ""
    val cursor = selectionStart.coerceIn(0, length)
    val lineStart = lastIndexOf('\n', (cursor - 1).coerceAtLeast(0)).let { if (it < 0) 0 else it + 1 }
    val lineEnd = indexOf('\n', cursor).let { if (it < 0) length else it }
    return substring(lineStart, lineEnd)
}

private val yamlSnippets = listOf(
    YamlSnippet("proxies", "proxies:\n  - name: proxy-name\n    type: ss\n"),
    YamlSnippet("proxy-groups", "proxy-groups:\n  - name: Proxy\n    type: select\n    proxies:\n      - DIRECT\n"),
    YamlSnippet("rules", "rules:\n  - MATCH,DIRECT\n"),
    YamlSnippet("dns", "dns:\n  enable: true\n  enhanced-mode: fake-ip\n"),
    YamlSnippet("rule-providers", "rule-providers:\n  example:\n    type: http\n    behavior: domain\n    path: ./rules/example.yaml\n    url: https://example.com/rules.yaml\n    interval: 86400\n"),
    YamlSnippet("proxy-providers", "proxy-providers:\n  example:\n    type: http\n    path: ./providers/example.yaml\n    url: https://example.com/provider.yaml\n    interval: 86400\n"),
    YamlSnippet("mixed-port", "mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\n"),
)

private val yamlCompletions = listOf(
    YamlSnippet("name", "name: \n"),
    YamlSnippet("type", "type: \n"),
    YamlSnippet("server", "server: \n"),
    YamlSnippet("port", "port: \n"),
    YamlSnippet("cipher", "cipher: \n"),
    YamlSnippet("password", "password: \n"),
    YamlSnippet("udp", "udp: true\n"),
    YamlSnippet("url", "url: \n"),
    YamlSnippet("interval", "interval: 86400\n"),
    YamlSnippet("behavior", "behavior: domain\n"),
    YamlSnippet("path", "path: ./providers/example.yaml\n"),
    YamlSnippet("MATCH", "MATCH,DIRECT\n"),
    YamlSnippet("DOMAIN-SUFFIX", "DOMAIN-SUFFIX,example.com,Proxy\n"),
    YamlSnippet("GEOIP", "GEOIP,CN,DIRECT\n"),
)

private fun TextFieldValue.insertYamlSnippet(snippet: String): TextFieldValue {
    val start = minOf(selection.start, selection.end).coerceIn(0, text.length)
    val end = maxOf(selection.start, selection.end).coerceIn(0, text.length)
    val before = text.substring(0, start)
    val after = text.substring(end)
    val insertion = snippet.withInsertionSpacing(before, after)
    val updatedText = before + insertion + after
    val cursor = before.length + insertion.length
    return copy(text = updatedText, selection = TextRange(cursor))
}

private fun String.withInsertionSpacing(before: String, after: String): String {
    if (before.isBlank() && after.isBlank()) return this
    return buildString {
        if (before.isNotBlank() && !before.endsWith("\n")) {
            append('\n')
        }
        append(this@withInsertionSpacing)
        if (after.isNotBlank() && !endsWith("\n") && !after.startsWith("\n")) {
            append('\n')
        }
    }
}

private fun TextFieldValue.indentSelectedYamlLines(): TextFieldValue {
    return transformSelectedYamlLines { "  $it" }
}

private fun TextFieldValue.outdentSelectedYamlLines(): TextFieldValue {
    return transformSelectedYamlLines { line ->
        when {
            line.startsWith("  ") -> line.drop(2)
            line.startsWith("\t") -> line.drop(1)
            line.startsWith(" ") -> line.drop(1)
            else -> line
        }
    }
}

private fun TextFieldValue.toggleYamlComment(): TextFieldValue {
    return transformSelectedYamlLines { line ->
        val indentLength = line.indexOfFirst { !it.isWhitespace() }.let { if (it < 0) line.length else it }
        val indent = line.take(indentLength)
        val body = line.drop(indentLength)
        if (body.startsWith("# ")) {
            indent + body.drop(2)
        } else if (body.startsWith("#")) {
            indent + body.drop(1)
        } else {
            "$indent# $body"
        }
    }
}

private fun TextFieldValue.cleanYamlWhitespace(): TextFieldValue {
    val updatedText = text
        .lines()
        .joinToString("\n") { line -> line.trimEnd() }
    return copy(
        text = updatedText,
        selection = TextRange(selection.start.coerceIn(0, updatedText.length), selection.end.coerceIn(0, updatedText.length)),
    )
}

private fun TextFieldValue.transformSelectedYamlLines(transform: (String) -> String): TextFieldValue {
    if (text.isEmpty()) return this

    val selectionStart = minOf(selection.start, selection.end).coerceIn(0, text.length)
    val selectionEnd = maxOf(selection.start, selection.end).coerceIn(0, text.length)
    val lineStart = text.lastIndexOf('\n', (selectionStart - 1).coerceAtLeast(0)).let { if (it < 0) 0 else it + 1 }
    val rawLineEnd = if (selectionEnd > selectionStart && selectionEnd <= text.length && text.getOrNull(selectionEnd - 1) == '\n') {
        selectionEnd - 1
    } else {
        selectionEnd
    }
    val lineEnd = text.indexOf('\n', rawLineEnd.coerceIn(0, text.length)).let { if (it < 0) text.length else it }
    val selectedBlock = text.substring(lineStart, lineEnd)
    val transformedBlock = selectedBlock
        .split('\n')
        .joinToString("\n") { line ->
            if (line.isBlank()) line else transform(line)
        }
    val updatedText = text.replaceRange(lineStart, lineEnd, transformedBlock)
    val selectionOffset = transformedBlock.length - selectedBlock.length
    val newSelection = if (selectionStart == selectionEnd) {
        TextRange((selectionStart + selectionOffset).coerceIn(0, updatedText.length))
    } else {
        TextRange(
            lineStart,
            (lineEnd + selectionOffset).coerceIn(0, updatedText.length),
        )
    }
    return copy(text = updatedText, selection = newSelection)
}

private fun String.yamlDiagnostics(): List<String> {
    if (isBlank()) return emptyList()
    val diagnostics = mutableListOf<String>()
    val topLevelKeys = mutableMapOf<String, Int>()
    var bracketDepth = 0
    var braceDepth = 0

    lineSequence().forEachIndexed { index, line ->
        val lineNumber = index + 1
        val trimmed = line.trim()
        if (trimmed.isBlank() || trimmed.startsWith("#")) return@forEachIndexed

        if (line.takeWhile { it.isWhitespace() }.contains('\t')) {
            diagnostics += "第 $lineNumber 行：缩进包含 Tab，YAML 建议只使用空格。"
        }

        val content = line.substringBefore("#").trimEnd()
        if (content.count { it == '"' } % 2 != 0) {
            diagnostics += "第 $lineNumber 行：双引号可能没有闭合。"
        }
        if (content.count { it == '\'' } % 2 != 0) {
            diagnostics += "第 $lineNumber 行：单引号可能没有闭合。"
        }

        bracketDepth += content.count { it == '[' } - content.count { it == ']' }
        braceDepth += content.count { it == '{' } - content.count { it == '}' }

        if (
            content.looksLikeYamlEntry() &&
            !content.contains(":") &&
            !content.startsWith("- ") &&
            !content.startsWith("!") &&
            !content.contains(",")
        ) {
            diagnostics += "第 $lineNumber 行：这一行看起来像配置项，但缺少冒号。"
        }

        topLevelKeyRegex.find(content)?.let { match ->
            val key = match.groupValues[1]
            val previousLine = topLevelKeys.putIfAbsent(key, lineNumber)
            if (previousLine != null) {
                diagnostics += "第 $lineNumber 行：顶层键 `$key` 与第 $previousLine 行重复。"
            }
        }
    }

    if (bracketDepth > 0) diagnostics += "方括号 `[` 可能没有闭合。"
    if (bracketDepth < 0) diagnostics += "方括号 `]` 数量多于 `[`。"
    if (braceDepth > 0) diagnostics += "花括号 `{` 可能没有闭合。"
    if (braceDepth < 0) diagnostics += "花括号 `}` 数量多于 `{`。"
    return diagnostics.distinct()
}

private fun String.looksLikeYamlEntry(): Boolean {
    if (isBlank()) return false
    val compact = trimStart()
    return compact.firstOrNull()?.isLetterOrDigit() == true || compact.startsWith("-")
}

private val topLevelKeyRegex = Regex("""^([A-Za-z0-9_-]+)\s*:""")

@Composable
private fun rememberYamlHighlightTransformation(
    searchMatches: List<IntRange>,
    activeSearchIndex: Int,
): VisualTransformation {
    val colors = MaterialTheme.colorScheme
    return remember(
        colors.primary,
        colors.tertiary,
        colors.secondary,
        colors.error,
        colors.outline,
        colors.primaryContainer,
        colors.secondaryContainer,
        searchMatches,
        activeSearchIndex,
    ) {
        YamlHighlightTransformation(
            keyColor = colors.primary,
            scalarColor = colors.tertiary,
            literalColor = colors.secondary,
            warningColor = colors.error,
            commentColor = colors.outline,
            searchColor = colors.secondaryContainer,
            activeSearchColor = colors.primaryContainer,
            searchMatches = searchMatches,
            activeSearchIndex = activeSearchIndex,
        )
    }
}

private class YamlHighlightTransformation(
    private val keyColor: Color,
    private val scalarColor: Color,
    private val literalColor: Color,
    private val warningColor: Color,
    private val commentColor: Color,
    private val searchColor: Color,
    private val activeSearchColor: Color,
    private val searchMatches: List<IntRange>,
    private val activeSearchIndex: Int,
) : VisualTransformation {
    override fun filter(text: AnnotatedString): TransformedText {
        val raw = text.text
        val builder = AnnotatedString.Builder(raw)
        var lineStart = 0
        raw.lineSequence().forEach { line ->
            highlightLine(builder, line, lineStart)
            lineStart += line.length + 1
        }
        searchMatches.forEachIndexed { index, range ->
            if (range.first >= 0 && range.last <= raw.length && range.first < range.last) {
                builder.addStyle(
                    SpanStyle(background = if (index == activeSearchIndex) activeSearchColor else searchColor),
                    range.first,
                    range.last,
                )
            }
        }
        return TransformedText(builder.toAnnotatedString(), OffsetMapping.Identity)
    }

    private fun highlightLine(
        builder: AnnotatedString.Builder,
        line: String,
        lineStart: Int,
    ) {
        val commentIndex = line.indexOf('#')
        val contentEnd = if (commentIndex >= 0) commentIndex else line.length
        if (commentIndex >= 0) {
            builder.addStyle(
                SpanStyle(color = commentColor, fontWeight = FontWeight.Normal),
                lineStart + commentIndex,
                lineStart + line.length,
            )
        }

        keyRegex.find(line)?.let { match ->
            val keyGroup = match.groups[1] ?: return@let
            if (keyGroup.range.first < contentEnd) {
                builder.addStyle(
                    SpanStyle(color = keyColor, fontWeight = FontWeight.SemiBold),
                    lineStart + keyGroup.range.first,
                    lineStart + keyGroup.range.last + 1,
                )
            }
        }

        scalarRegex.findAll(line.substring(0, contentEnd)).forEach { match ->
            builder.addStyle(
                SpanStyle(color = scalarColor, fontWeight = FontWeight.Medium),
                lineStart + match.range.first,
                lineStart + match.range.last + 1,
            )
        }

        literalRegex.findAll(line.substring(0, contentEnd)).forEach { match ->
            builder.addStyle(
                SpanStyle(color = literalColor),
                lineStart + match.range.first,
                lineStart + match.range.last + 1,
            )
        }

        if (line.take(contentEnd).contains("!!")) {
            builder.addStyle(
                SpanStyle(color = warningColor, fontWeight = FontWeight.Bold),
                lineStart,
                lineStart + contentEnd,
            )
        }
    }

    companion object {
        private val keyRegex = Regex("""^\s*-?\s*([A-Za-z0-9_-]+)\s*:""")
        private val scalarRegex = Regex("""(?<![A-Za-z0-9_-])(true|false|null|rule|global|direct|select|url-test|fallback|load-balance|http|file|domain|ipcidr|classical)(?![A-Za-z0-9_-])""", RegexOption.IGNORE_CASE)
        private val literalRegex = Regex("""(?<![A-Za-z0-9_-])(\d+|DIRECT|REJECT|Proxy|MATCH|DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|GEOIP|IP-CIDR|PROCESS-NAME)(?![A-Za-z0-9_-])""")
    }
}

private fun String.searchMatches(query: String): List<IntRange> {
    val keyword = query.trim()
    if (keyword.isBlank()) return emptyList()
    val matches = mutableListOf<IntRange>()
    var startIndex = 0
    while (startIndex < length) {
        val index = indexOf(keyword, startIndex, ignoreCase = true)
        if (index < 0) break
        matches += index until index + keyword.length
        startIndex = index + keyword.length
    }
    return matches
}
