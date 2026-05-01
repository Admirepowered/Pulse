#if defined(__ANDROID__) && defined(__aarch64__)
__thread char pulse_android_tls_alignment_anchor __attribute__((used, aligned(64))) = 1;
#endif
