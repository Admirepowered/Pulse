# Pulse Proxy ProGuard rules
-keepattributes *Annotation*
-keep class com.pulse.proxy.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**
