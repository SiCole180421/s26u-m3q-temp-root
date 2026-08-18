package dev.indevelopment.m3qroot;

final class LogRedactor {
    private LogRedactor() {
    }

    static String dropPartialFirstLine(String text) {
        int newline = text.indexOf('\n');
        return newline >= 0 ? text.substring(newline + 1) : "";
    }

    static String redact(String text) {
        return "[공유용 정제 로그: 원본 last-root.log는 앱 내부에 유지]\n"
                + text
                .replaceAll("(?i)(boot[_ -]?id\\s*[:=]\\s*)[0-9a-f-]{32,36}",
                        "$1<redacted-boot-id>")
                .replaceAll("(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b",
                        "<redacted-uuid>")
                .replaceAll("(?i)\\b(?:0x)?ffff[0-9a-f]{8,16}\\b",
                        "<redacted-kernel-address>")
                .replaceAll("(?i)\\b(pid|tid|keeper(?:_pid)?)\\s*[:=]\\s*\\d+",
                        "$1=<redacted>")
                .replaceAll("(?i)\\b(?:ppid|tgid|child(?:_pid)?|[a-z0-9_]*_child|"
                                + "adbd|system_server|parent|consumer|producer|waiter|holder|"
                                + "uid|euid|gid|egid|client_uid|app_uid)\\s*[:=]\\s*\\d+",
                        "process-id=<redacted>")
                .replaceAll("(?i)\\bR[0-9A-Z]{10}\\b", "<redacted-device-serial>")
                .replaceAll("(?i)/data/(?:app|user|user_de|local|adb)/[^\\s\"']+",
                        "/data/<redacted>");
    }
}
