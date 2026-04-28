package com.pulse.proxy.util

import com.pulse.proxy.data.LogEntry
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class LogBuffer(private val maxSize: Int = 500) {
    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries.asStateFlow()

    fun append(message: String) {
        val current = _entries.value.toMutableList()
        current.add(LogEntry(message = message))
        if (current.size > maxSize) {
            _entries.value = current.drop(current.size - maxSize)
        } else {
            _entries.value = current
        }
    }

    fun clear() {
        _entries.value = emptyList()
    }
}
