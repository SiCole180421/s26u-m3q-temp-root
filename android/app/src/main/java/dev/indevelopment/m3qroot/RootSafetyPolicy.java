package dev.indevelopment.m3qroot;

final class RootSafetyPolicy {
    private static final long MIN_ROOT_BOOT_UPTIME_MILLIS = 180_000L;

    private RootSafetyPolicy() {
    }

    static long bootSettleRemainingMillis(long elapsedRealtimeMillis) {
        return Math.max(0L, MIN_ROOT_BOOT_UPTIME_MILLIS - elapsedRealtimeMillis);
    }
}
