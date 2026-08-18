package dev.indevelopment.m3qroot;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.SystemClock;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Context-only root workflow shared by the activity and foreground service. */
final class M3qRootEngine {
    interface Listener {
        void onStatus(String text, int color);

        void onLog(String line);
    }

    record RootState(boolean kernelSu, boolean bootstrap,
                     boolean terminationUnconfirmed, String output) {
        boolean ready() {
            return kernelSu;
        }
    }

    private static final String MODEL = "SM-S948B";
    private static final String KERNEL =
            "6.12.30-android16-5-pd30ff70-abogkiS948BXXS4AZG5-4k";
    private static final String FINGERPRINT =
            "samsung/m3qxeea/m3q:16/BP4A.251205.006/" +
                    "S948BXXS4AZG5_OXM4AZG5:user/release-keys";
    private static final long KIMAGE_BASE = 0xffffffc080000000L;
    private static final String HELPER = "libm3qroot.so";
    private static final String ORACLE = "libm3qoracle.so";
    private static final String PAYLOAD = "libm3qpayload.so";
    private static final String KSUD = "libm3qksud.so";
    private static final String KSU_LOADER_PATH =
            "/data/local/tmp/ksud-m3q-S948BXXS4AZG5-kdp";
    private static final String KSU_STAGE_PATH = "/data/local/tmp/.ksud-stage";
    private static final String KSU_LOG_PATH =
            "/data/local/tmp/m3q-kernelsu-late-load.log";
    private static final String KSU_MANAGER_PACKAGE = "me.weishu.kernelsu";
    private static final String MODULE_RELOAD_HOOK_DIR = "/data/adb/boot-completed.d";
    private static final String KSUD_SHA256 =
            "a813691ee911d12b08bacfd13a2acd54ced595599419b8b3a69f7d975d20d793";
    private static final String SAFETY_PREFS = "kernel_run_safety";
    private static final String ATTEMPT_BOOT_ID = "attempt_boot_id";
    private static final String VERIFIED_KSU_BOOT_ID = "verified_ksu_boot_id";
    private static final String BOOT_ID_PATH = "/proc/sys/kernel/random/boot_id";
    private static final int STATUS_WORKING = 0xff9a6700;
    static final int EXIT_TERMINATION_UNCONFIRMED = -1001;
    private static final long TERMINATION_WAIT_SECONDS = 3;
    private static final long READER_JOIN_SECONDS = 2;
    private static final Object ATTEMPT_LOCK = new Object();

    private static final Pattern ORACLE_KASLR = Pattern.compile(
            "slide-kaslr-ok source=physical .*?base=([0-9a-fA-F]+) " +
                    "slide=([0-9a-fA-F]+)");
    private static final Pattern ORACLE_DONE = Pattern.compile(
            "slide-only done base=([0-9a-fA-F]+) slide=([0-9a-fA-F]+) " +
                    "p0_offset=([0-9a-fA-F]+)");
    private static final Pattern ORACLE_KEEPER = Pattern.compile(
            "p0 reference keeper pid=([0-9]+) pipe=([0-9]+)");

    private final Context context;
    private final Listener listener;

    M3qRootEngine(Context context, Listener listener) {
        Objects.requireNonNull(context, "context");
        Context application = context.getApplicationContext();
        this.context = application != null ? application : context;
        this.listener = Objects.requireNonNull(listener, "listener");
    }

    boolean isSupported() {
        return MODEL.equals(Build.MODEL)
                && KERNEL.equals(System.getProperty("os.version", ""))
                && FINGERPRINT.equals(Build.FINGERPRINT);
    }

    RootState checkRoot(boolean verbose) {
        File helper = nativeFile(HELPER);
        if (!helper.isFile()) {
            return new RootState(false, false, false, "helper missing");
        }

        List<String> ksuLines = new ArrayList<>();
        int ksuCode = 127;
        boolean authoritativeProbe = false;
        if (ShizukuShell.isRunning() && ShizukuShell.isGranted()) {
            int uid = ShizukuShell.uid();
            if (uid == 2000 || uid == 0) {
                String[] command = {helper.getAbsolutePath(), "--ksu-info"};
                String[] environment = {
                        "HOME=/data/local/tmp",
                        "TMPDIR=/data/local/tmp",
                        "PATH=/system/bin:/system/xbin"
                };
                try {
                    Process process = ShizukuShell.exec(
                            command, environment, "/data/local/tmp");
                    authoritativeProbe = true;
                    ksuCode = runProcess(process, 8, ksuLines, verbose);
                } catch (RuntimeException e) {
                    if (verbose) log("Shizuku KernelSU 확인 오류: " + e.getMessage());
                    if (e instanceof ShizukuShell.ProcessControlLostException) {
                        return new RootState(false, false, true, e.getMessage());
                    }
                }
            }
        }
        if (Thread.currentThread().isInterrupted()) {
            return new RootState(false, false, false, "interrupted");
        }
        String ksuOutput = String.join("\n", ksuLines);
        if (ksuCode == EXIT_TERMINATION_UNCONFIRMED) {
            return new RootState(false, false, true, ksuOutput);
        }
        boolean kernelSu = ksuCode == 0
                && ksuOutput.contains("KernelSU control verified version=32525");
        if (kernelSu) {
            markKernelSuVerifiedForThisBoot();
            return new RootState(true, false, false, ksuOutput);
        }
        if (!authoritativeProbe && hasVerifiedKernelSuThisBoot()) {
            return new RootState(true, false, false,
                    "KernelSU control verified by the root daemon for this boot");
        }

        ProcessBuilder bootstrap = new ProcessBuilder(
                helper.getAbsolutePath(), "-c", "id");
        bootstrap.redirectErrorStream(true);
        List<String> bootstrapLines = new ArrayList<>();
        int bootstrapCode = runProcess(bootstrap, 8, bootstrapLines, verbose);
        String bootstrapOutput = String.join("\n", bootstrapLines);
        if (bootstrapCode == EXIT_TERMINATION_UNCONFIRMED) {
            return new RootState(false, false, true,
                    ksuOutput + "\n" + bootstrapOutput);
        }
        return new RootState(false,
                bootstrapCode == 0 && bootstrapOutput.contains("uid=0(root)"),
                false,
                ksuOutput + "\n" + bootstrapOutput);
    }

    int runFreshRoot(boolean useShizuku) {
        File helper = nativeFile(HELPER);
        File oracle = nativeFile(ORACLE);
        File payload = nativeFile(PAYLOAD);
        File ksud = nativeFile(KSUD);
        if (!helper.isFile() || !payload.isFile() || !ksud.isFile()
                || (!useShizuku && !oracle.isFile())) {
            log("필요한 네이티브 파일을 APK에서 찾지 못했습니다.");
            return 126;
        }

        if (useShizuku) {
            int rootCode = runShizukuTracefsRoot(helper, payload);
            return rootCode == 0 ? activateKernelSu(helper, ksud) : rootCode;
        }

        status("기기 보안 상태 확인 중", STATUS_WORKING);
        log("1/2: 정확한 Image fingerprint로 물리 P0 slide 확인");
        List<String> oracleLines = new ArrayList<>();
        ProcessBuilder oracleProcess = payloadProcess(helper, oracle);
        Map<String, String> oracleEnv = oracleProcess.environment();
        oracleEnv.put("SLIDE_ONLY", "1");
        oracleEnv.put("P0_ONLY", "1");
        oracleEnv.put("EXPLOIT_ATTEMPTS", "1");
        oracleEnv.put("P0_MIN_BOOT_UPTIME_SEC", "30");
        oracleEnv.put("P0_ATTEMPT_TIMEOUT_SEC", "90");
        oracleEnv.put("EXPLOIT_ATTEMPT_TIMEOUT_SEC", "120");
        int oracleCode = runProcess(oracleProcess, 150, oracleLines, true);
        if (oracleCode != 0) {
            log("P0 oracle 실패: write 상태가 불명확하면 재부팅 후 다시 시도하세요.");
            return oracleCode;
        }

        SlideVerdict verdict = parseOracleVerdict(oracleLines);
        if (verdict == null) {
            log("P0 oracle 출력의 유일하고 일관된 slide verdict를 확인하지 못했습니다.");
            return 125;
        }
        if (verdict.keeperPid() > 0) {
            android.os.Process.killProcess(verdict.keeperPid());
            log("복원 완료 후 P0 reference keeper 종료 pid=" + verdict.keeperPid());
        }
        log("P0 slide 확정: " + verdict.argument());

        status("임시 루트 활성화 중", STATUS_WORKING);
        log("2/2: 검증된 slide로 AZG5 root-single 실행");
        ProcessBuilder rootProcess = payloadProcess(helper, payload);
        Map<String, String> env = rootProcess.environment();
        configureRootEnvironment(env, false, verdict.argument());
        List<String> rootLines = new ArrayList<>();
        int rootCode = runProcess(rootProcess, 600, rootLines, true);
        if (rootCode != EXIT_TERMINATION_UNCONFIRMED) {
            saveRootLog(rootLines, rootCode);
        } else {
            log("프로세스 종료를 확인하지 못해 root 로그 확정을 생략합니다.");
        }
        return rootCode == 0 ? activateKernelSu(helper, ksud) : rootCode;
    }

    int activateKernelSu() {
        return activateKernelSu(nativeFile(HELPER), nativeFile(KSUD));
    }

    int reapplyKernelSuModules() {
        File ksud = nativeFile(KSUD);
        if (!ksud.isFile()) {
            log("KernelSU 실행 파일을 APK에서 찾지 못했습니다.");
            return 126;
        }

        String token = Long.toHexString(SystemClock.elapsedRealtimeNanos());
        String marker = "/data/local/tmp/.m3q-module-reload-" + token;
        String hook = MODULE_RELOAD_HOOK_DIR
                + "/99-m3q-module-reload-" + token + ".sh";
        String command = kernelSuRootPreamble(ksud)
                + "stage=" + shellQuote(KSU_STAGE_PATH) + "\n"
                + "hook=" + shellQuote(hook) + "\n"
                + "marker=" + shellQuote(marker) + "\n"
                + "cleanup() { rm -f -- \"$stage\" \"$hook\" \"$marker\"; }\n"
                + "trap cleanup EXIT HUP INT TERM\n"
                + "rm -f -- \"$stage\"\n"
                + "cp \"$ksud\" \"$stage\"\n"
                + "chmod 0755 \"$stage\"\n"
                + "stage_hash=$(sha256sum \"$stage\"); stage_hash=${stage_hash%% *}\n"
                + "if [ \"$stage_hash\" != \"$hash\" ]; then\n"
                + "  echo M3Q_KSUD_STAGE_HASH_MISMATCH:$stage_hash\n"
                + "  exit 125\n"
                + "fi\n"
                + "mkdir -p " + shellQuote(MODULE_RELOAD_HOOK_DIR) + "\n"
                + "rm -f -- \"$hook\" \"$marker\"\n"
                + "cat > \"$hook\" <<'M3Q_MODULE_RELOAD_HOOK'\n"
                + "#!/system/bin/sh\n"
                + "printf '%s\\n' " + shellQuote(token) + " > "
                + shellQuote(marker) + "\n"
                + "rm -f -- \"$0\"\n"
                + "exit 0\n"
                + "M3Q_MODULE_RELOAD_HOOK\n"
                + "chmod 0755 \"$hook\"\n"
                + "\"$ksud\" late-load --kmi android16-6.12 --package-name "
                + KSU_MANAGER_PACKAGE + "\n"
                + "i=0\n"
                + "while [ \"$i\" -lt 120 ]; do\n"
                + "  if [ -f \"$marker\" ]; then\n"
                + "    echo M3Q_MODULE_RELOAD_OK:" + token + "\n"
                + "    exit 0\n"
                + "  fi\n"
                + "  i=$((i + 1))\n"
                + "  sleep 1\n"
                + "done\n"
                + "echo M3Q_MODULE_RELOAD_TIMEOUT\n"
                + "exit 124\n";

        status("KernelSU 모듈 재로드 중", STATUS_WORKING);
        List<String> output = new ArrayList<>();
        int code = runKernelSuRootCommand(ksud, command, 150, output);
        if (code != 0) {
            log("KernelSU 모듈 재적용 실패 code=" + code);
            return code;
        }
        if (!String.join("\n", output).contains("M3Q_MODULE_RELOAD_OK:" + token)) {
            log("KernelSU boot-completed 단계의 완료 표식을 확인하지 못했습니다.");
            return 125;
        }
        log("KernelSU 모듈 late-load 재적용 완료");
        return 0;
    }

    int restartZygote() {
        File ksud = nativeFile(KSUD);
        if (!ksud.isFile()) {
            log("KernelSU 실행 파일을 APK에서 찾지 못했습니다.");
            return 126;
        }
        String command = kernelSuRootPreamble(ksud)
                + "echo M3Q_ZYGOTE_RESTART_REQUESTED\n"
                + "if [ \"$(getprop init.svc.zygote_secondary)\" = running ]; then\n"
                + "  setprop ctl.restart zygote_secondary\n"
                + "fi\n"
                + "setprop ctl.restart zygote\n";
        return runKernelSuRootCommand(ksud, command, 15, new ArrayList<>());
    }

    String currentBootId() {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(
                new FileInputStream(BOOT_ID_PATH), StandardCharsets.US_ASCII))) {
            String bootId = in.readLine();
            return bootId == null ? "" : bootId.trim();
        } catch (IOException e) {
            return "";
        }
    }

    static long bootSettleRemainingMillis() {
        return RootSafetyPolicy.bootSettleRemainingMillis(SystemClock.elapsedRealtime());
    }

    boolean markAttemptForThisBoot() {
        if (bootSettleRemainingMillis() > 0) return false;
        synchronized (ATTEMPT_LOCK) {
            String bootId = currentBootId();
            if (bootId.isEmpty()) return false;
            SharedPreferences prefs = preferences();
            if (bootId.equals(prefs.getString(ATTEMPT_BOOT_ID, ""))) return false;
            return prefs.edit().putString(ATTEMPT_BOOT_ID, bootId).commit();
        }
    }

    boolean hasAttemptedThisBoot() {
        String bootId = currentBootId();
        if (bootId.isEmpty()) return true;
        String attempted = preferences().getString(ATTEMPT_BOOT_ID, "");
        return bootId.equals(attempted);
    }

    boolean hasVerifiedKernelSuThisBoot() {
        String bootId = currentBootId();
        if (bootId.isEmpty()) return false;
        String verified = preferences().getString(VERIFIED_KSU_BOOT_ID, "");
        return bootId.equals(verified);
    }

    File lastRootLog() {
        File directory = context.getExternalFilesDir(null);
        if (directory == null) directory = context.getFilesDir();
        return new File(directory, "last-root.log");
    }

    private int runShizukuTracefsRoot(File helper, File payload) {
        int uid = ShizukuShell.uid();
        if (uid != 2000 && uid != 0) {
            log("Shizuku가 shell/root UID가 아니므로 실행을 거부합니다.");
            return 126;
        }
        status("Shizuku로 임시 루트 활성화 중", STATUS_WORKING);
        log("1/1: shell tracefs KASLR gate로 AZG5 root-single 실행");
        Map<String, String> env = new HashMap<>();
        env.put("HOME", "/data/local/tmp");
        env.put("TMPDIR", "/data/local/tmp");
        env.put("PATH", "/system/bin:/system/xbin");
        configureRootEnvironment(env, true, null);
        String[] environment = new String[env.size()];
        int index = 0;
        for (Map.Entry<String, String> entry : env.entrySet()) {
            environment[index++] = entry.getKey() + "=" + entry.getValue();
        }
        String[] command = {
                helper.getAbsolutePath(), "--run-payload",
                payload.getAbsolutePath(), helper.getAbsolutePath()
        };
        try {
            Process process = ShizukuShell.exec(command, environment, "/data/local/tmp");
            List<String> rootLines = new ArrayList<>();
            int rootCode = runProcess(process, 600, rootLines, true);
            if (rootCode != EXIT_TERMINATION_UNCONFIRMED) {
                saveRootLog(rootLines, rootCode);
            } else {
                log("프로세스 종료를 확인하지 못해 root 로그 확정을 생략합니다.");
            }
            return rootCode;
        } catch (RuntimeException e) {
            log("Shizuku 실행 오류: " + e.getMessage());
            return e instanceof ShizukuShell.ProcessControlLostException
                    ? EXIT_TERMINATION_UNCONFIRMED : 127;
        }
    }

    private void configureRootEnvironment(Map<String, String> env,
                                          boolean tracefs, String slide) {
        env.put("M3Q_STAGE", "root-single");
        env.put("M3Q_APP_UID", Integer.toString(android.os.Process.myUid()));
        env.put("M3Q_ENABLE_WRITE", "1");
        env.put("M3Q_REQUIRE_TRACEFS", tracefs ? "1" : "0");
        env.put("M3Q_REQUIRE_APP_P0", tracefs ? "0" : "1");
        if (!tracefs) {
            env.put("M3Q_APP_P0_SOURCE", "physical");
            env.put("M3Q_APP_P0_VERDICT", "exact-fingerprint-32x8");
            env.put("SLIDE_P0_OFFSET", slide);
        }
        env.put("M3Q_POPSICLE_WALK", "1");
        env.put("M3Q_ATTR_CARRIER", "1");
        env.put("M3Q_ATTR_ROOT", "1");
        env.put("M3Q_ACCEPT_PANIC_RISK", "1");
        env.put("TMP_PAGE_UNAME", "1");
        env.put("TMP_UNAME_PIPEI_SWEEP", "1");
        env.put("TMP_UNAME_PIPEI_SLOT_CANDIDATES", "1");
        env.put("TMP_UNAME_PIPEI_MAX_ATTEMPTS", "1");
        env.put("GHOSTLOCK_CORE", "6");
        env.put("GHOSTLOCK_CONSUMER_CORE", "7");
        env.put("PSELECT_RECLAIM_CORE", "2");
        env.put("PSELECT_RECLAIM_SINGLE_FRAG", "1");
        env.put("PSELECT_RECLAIM_SENDS", "8");
        env.put("PSELECT_RECLAIM_SINGLE_SYSCALL", "1");
        env.put("PSELECT_PREPARE_SLABS", "8");
        env.put("PSELECT_GRAB_HOLD", "0");
        env.put("PSELECT_MM_KICK_SLABS", "0");
        env.put("PSELECT_OWNER_NULL", "1");
        env.put("PSELECT_REAL_WAITER_TASK", "1");
        env.put("PSELECT_W0_PRIO_OVERRIDE", "100");
        env.put("PSELECT_ROUTE_TIMERFD", "0");
        env.put("PSELECT_ROUTE_TIMEOUT_SEC", "1");
        env.put("PSELECT_ROUTE_WAIT_SECONDS", "1");
        env.put("M3Q_SKB_METADATA_RESERVE", "0");
        env.put("M3Q_DMAHEAP_SWEEP", "0");
        env.put("M3Q_DRAIN_CHILDREN", "0");
        env.put("PIPEI_DRAIN_TARGET_MB", "0");
        env.put("PIPEI_PIN_ENABLE", "0");
        env.put("PIPEI_PIN_CHILD", "0");
        env.put("PIPEI_ORACLE_WALK", "1");
        env.put("PIPEI_ORACLE_REGION", "3");
        env.put("PIPEI_ORACLE_INLINE", "0");
        env.put("PIPEI_CHILD_REGIONS", "5");
        env.put("PIPEI_SWEEP_INLINE", "0");
        env.put("M3Q_WORKSPACE_ATTEMPTS", "3");
        env.put("M3Q_PROBE_STRICT", "1");
    }

    private int activateKernelSu(File helper, File ksud) {
        if (!helper.isFile() || !ksud.isFile()) {
            log("KernelSU loader를 APK에서 찾지 못했습니다.");
            return 126;
        }

        status("KernelSU 구성 확인 중", STATUS_WORKING);
        String source = shellQuote(ksud.getAbsolutePath());
        String loader = shellQuote(KSU_LOADER_PATH);
        String stage = shellQuote(KSU_STAGE_PATH);
        String command = "set -eu; umask 022; mkdir -p /data/adb; " +
                "cp " + source + " " + loader + "; " +
                "cp " + source + " " + stage + "; " +
                "chmod 0755 " + loader + " " + stage + "; " +
                "h1=$(sha256sum " + loader + "); h1=${h1%% *}; " +
                "h2=$(sha256sum " + stage + "); h2=${h2%% *}; " +
                "test \"$h1\" = " + KSUD_SHA256 + "; " +
                "test \"$h2\" = " + KSUD_SHA256 + "; " +
                "echo KSU_STAGE_OK:$h1";

        List<String> stageLines = new ArrayList<>();
        ProcessBuilder stageProcess = new ProcessBuilder(
                helper.getAbsolutePath(), "-c", command);
        stageProcess.redirectErrorStream(true);
        int stageCode = runProcess(stageProcess, 30, stageLines, true);
        if (Thread.currentThread().isInterrupted()) return stageCode;
        if (stageCode == EXIT_TERMINATION_UNCONFIRMED
                || stageCode == 124 || stageCode == 130) {
            return EXIT_TERMINATION_UNCONFIRMED;
        }
        String stageOutput = String.join("\n", stageLines);
        String expectedMarker = "KSU_STAGE_OK:" + KSUD_SHA256;
        if (stageCode != 0 || !stageOutput.contains(expectedMarker)) {
            log("KernelSU staging 검증 실패");
            return 125;
        }

        log("KernelSU loader SHA-256 일치");
        status("KernelSU 활성화 중", STATUS_WORKING);
        ProcessBuilder loadProcess = new ProcessBuilder(
                helper.getAbsolutePath(), "--late-load");
        loadProcess.redirectErrorStream(true);
        int loadCode = runProcess(loadProcess, 180);
        if (Thread.currentThread().isInterrupted()) return loadCode;
        if (loadCode == EXIT_TERMINATION_UNCONFIRMED
                || loadCode == 124 || loadCode == 130) {
            return EXIT_TERMINATION_UNCONFIRMED;
        }
        if (loadCode != 0) {
            log("KernelSU late-load 실패 code=" + loadCode);
            appendKernelSuLog(helper);
            return loadCode;
        }

        /* The daemon verifies KernelSU in a seccomp-free context. A direct
         * untrusted_app discovery syscall is killed by Samsung seccomp. */
        if (!markKernelSuVerifiedForThisBoot()) {
            log("KernelSU는 로드됐지만 이 boot ID의 검증 영수증을 저장하지 못했습니다.");
            return 123;
        }

        RootState state = checkRoot(true);
        if (state.terminationUnconfirmed()) {
            return EXIT_TERMINATION_UNCONFIRMED;
        }
        if (!state.ready()) {
            log("late-load는 끝났지만 KernelSU control 검증이 실패했습니다.");
            return 124;
        }
        log("KernelSU 3.2.5 LKM late-load 검증 완료");
        return 0;
    }

    private void appendKernelSuLog(File helper) {
        ProcessBuilder logProcess = new ProcessBuilder(
                helper.getAbsolutePath(), "-c",
                "test ! -r " + shellQuote(KSU_LOG_PATH) + " || cat " +
                        shellQuote(KSU_LOG_PATH));
        logProcess.redirectErrorStream(true);
        runProcess(logProcess, 10);
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private String kernelSuRootPreamble(File ksud) {
        return "set -eu\n"
                + "ksud=" + shellQuote(ksud.getAbsolutePath()) + "\n"
                + "if [ \"$(id -u)\" != 0 ]; then\n"
                + "  echo M3Q_ROOT_PERMISSION_REQUIRED\n"
                + "  exit 126\n"
                + "fi\n"
                + "hash=$(sha256sum \"$ksud\"); hash=${hash%% *}\n"
                + "if [ \"$hash\" != " + KSUD_SHA256 + " ]; then\n"
                + "  echo M3Q_KSUD_HASH_MISMATCH:$hash\n"
                + "  exit 125\n"
                + "fi\n"
                + "info=$(\"$ksud\" debug info 2>&1)\n"
                + "printf '%s\\n' \"$info\"\n"
                + "printf '%s\\n' \"$info\" | grep -Fqx 'version: 32525' || exit 125\n"
                + "printf '%s\\n' \"$info\" | grep -Fqx 'late_load: true' || exit 125\n";
    }

    private int runKernelSuRootCommand(File ksud, String command, int timeoutSeconds,
                                       List<String> output) {
        ProcessBuilder processBuilder = new ProcessBuilder(
                ksud.getAbsolutePath(), "debug", "su", "-g");
        processBuilder.directory(context.getFilesDir());
        processBuilder.redirectErrorStream(true);
        processBuilder.environment().put("HOME", "/data/local/tmp");
        processBuilder.environment().put("TMPDIR", "/data/local/tmp");
        processBuilder.environment().put("PATH", "/system/bin:/system/xbin");
        try {
            Process process = processBuilder.start();
            try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                    process.getOutputStream(), StandardCharsets.UTF_8))) {
                writer.write(command);
                writer.newLine();
                writer.write("exit");
                writer.newLine();
            }
            return runProcess(process, timeoutSeconds, output, true);
        } catch (IOException e) {
            log("KernelSU root shell 실행 오류: " + e.getMessage());
            return 127;
        }
    }

    private ProcessBuilder payloadProcess(File helper, File payload) {
        ProcessBuilder process = new ProcessBuilder(
                helper.getAbsolutePath(), "--run-payload",
                payload.getAbsolutePath(), helper.getAbsolutePath());
        process.directory(context.getFilesDir());
        process.redirectErrorStream(true);
        process.environment().put("HOME", context.getFilesDir().getAbsolutePath());
        process.environment().put("TMPDIR", context.getCacheDir().getAbsolutePath());
        return process;
    }

    private SlideVerdict parseOracleVerdict(List<String> lines) {
        Long kaslrBase = null;
        Long kaslrSlide = null;
        Long doneBase = null;
        Long doneSlide = null;
        Long p0Offset = null;
        int keeperPid = -1;
        try {
            for (String line : lines) {
                Matcher kaslr = ORACLE_KASLR.matcher(line);
                if (kaslr.find()) {
                    if (kaslrBase != null) return null;
                    kaslrBase = Long.parseUnsignedLong(kaslr.group(1), 16);
                    kaslrSlide = Long.parseUnsignedLong(kaslr.group(2), 16);
                }
                Matcher done = ORACLE_DONE.matcher(line);
                if (done.find()) {
                    if (doneBase != null) return null;
                    doneBase = Long.parseUnsignedLong(done.group(1), 16);
                    doneSlide = Long.parseUnsignedLong(done.group(2), 16);
                    p0Offset = Long.parseUnsignedLong(done.group(3), 16);
                }
                Matcher keeper = ORACLE_KEEPER.matcher(line);
                if (keeper.find()) {
                    keeperPid = Integer.parseInt(keeper.group(1));
                }
            }
        } catch (NumberFormatException ignored) {
            return null;
        }
        if (kaslrBase == null || kaslrSlide == null || doneBase == null
                || doneSlide == null || p0Offset == null
                || !kaslrBase.equals(doneBase) || !kaslrSlide.equals(doneSlide)
                || !kaslrSlide.equals(p0Offset) || kaslrSlide > 0x1f0000L
                || (kaslrSlide & 0xffffL) != 0
                || kaslrBase != KIMAGE_BASE + kaslrSlide) {
            return null;
        }
        return new SlideVerdict(kaslrSlide,
                String.format(Locale.ROOT, "0x%x", kaslrSlide), keeperPid);
    }

    private boolean markKernelSuVerifiedForThisBoot() {
        String bootId = currentBootId();
        if (bootId.isEmpty()) return false;
        return preferences().edit()
                .putString(VERIFIED_KSU_BOOT_ID, bootId).commit();
    }

    private SharedPreferences preferences() {
        return context.getSharedPreferences(SAFETY_PREFS, Context.MODE_PRIVATE);
    }

    private int runProcess(ProcessBuilder process, int timeoutSeconds) {
        return runProcess(process, timeoutSeconds, null, true);
    }

    private int runProcess(ProcessBuilder process, int timeoutSeconds,
                           List<String> capture, boolean display) {
        try {
            return runProcess(process.start(), timeoutSeconds, capture, display);
        } catch (IOException e) {
            if (display) log("실행 오류: " + e.getMessage());
            return 127;
        }
    }

    private int runProcess(Process process, int timeoutSeconds,
                           List<String> capture, boolean display) {
        InputStream processStdout = process.getInputStream();
        InputStream processStderr = process.getErrorStream();
        Thread stdout = streamReader(processStdout, capture, display,
                "m3q-root-stdout");
        Thread stderr = streamReader(processStderr, capture, display,
                "m3q-root-stderr");
        stdout.start();
        stderr.start();
        boolean[] interrupted = {false};
        boolean processEnded = false;
        int result = 127;
        try {
            processEnded = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (processEnded) {
                result = process.exitValue();
            } else {
                processEnded = terminateAndWait(process, interrupted);
                result = processEnded ? 124 : EXIT_TERMINATION_UNCONFIRMED;
            }
        } catch (InterruptedException e) {
            interrupted[0] = true;
            processEnded = terminateAndWait(process, interrupted);
            result = processEnded ? 130 : EXIT_TERMINATION_UNCONFIRMED;
        } catch (RuntimeException e) {
            processEnded = terminateAndWait(process, interrupted);
            if (display) log("실행 오류: " + e.getMessage());
            result = processEnded ? 127 : EXIT_TERMINATION_UNCONFIRMED;
        } finally {
            closeQuietly(process.getOutputStream());
            if (!processEnded) {
                closeQuietly(processStdout);
                closeQuietly(processStderr);
            }
            boolean stdoutDone = joinReader(stdout, READER_JOIN_SECONDS, interrupted);
            boolean stderrDone = joinReader(stderr, READER_JOIN_SECONDS, interrupted);
            if (!stdoutDone || !stderrDone) {
                closeQuietly(processStdout);
                closeQuietly(processStderr);
                stdoutDone = joinReader(stdout, 1, interrupted);
                stderrDone = joinReader(stderr, 1, interrupted);
            }
            closeQuietly(processStdout);
            closeQuietly(processStderr);
            if (display && (!stdoutDone || !stderrDone)) {
                log("프로세스 출력 stream 종료를 확인하지 못했습니다.");
            }
            if (interrupted[0]) Thread.currentThread().interrupt();
        }
        if (result == EXIT_TERMINATION_UNCONFIRMED && display) {
            log("프로세스 그룹 종료를 확인하지 못했습니다. 이 boot에서 재시도하지 마세요.");
        }
        return result;
    }

    private static boolean terminateAndWait(Process process, boolean[] interrupted) {
        try {
            process.destroy();
        } catch (RuntimeException ignored) {
        }
        if (awaitProcessExit(process, TERMINATION_WAIT_SECONDS, interrupted)) {
            return true;
        }
        try {
            process.destroyForcibly();
        } catch (RuntimeException ignored) {
        }
        return awaitProcessExit(process, TERMINATION_WAIT_SECONDS, interrupted);
    }

    private static boolean awaitProcessExit(Process process, long timeoutSeconds,
                                            boolean[] interrupted) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (true) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) return false;
            try {
                if (process.waitFor(Math.min(remaining,
                        TimeUnit.MILLISECONDS.toNanos(250)), TimeUnit.NANOSECONDS)) {
                    return true;
                }
            } catch (InterruptedException ignored) {
                interrupted[0] = true;
            } catch (RuntimeException ignored) {
                return false;
            }
        }
    }

    private static boolean joinReader(Thread reader, long timeoutSeconds,
                                      boolean[] interrupted) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (reader.isAlive()) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) break;
            try {
                reader.join(Math.max(1, Math.min(
                        TimeUnit.NANOSECONDS.toMillis(remaining), 250)));
            } catch (InterruptedException ignored) {
                interrupted[0] = true;
            }
        }
        if (reader.isAlive()) reader.interrupt();
        return !reader.isAlive();
    }

    private static void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException ignored) {
        }
    }

    private Thread streamReader(InputStream stream, List<String> capture,
                                boolean display, String name) {
        Thread reader = new Thread(() -> {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(
                    stream, StandardCharsets.UTF_8))) {
                String line;
                while ((line = in.readLine()) != null) {
                    if (capture != null) {
                        synchronized (capture) {
                            capture.add(line);
                        }
                    }
                    if (display) log(line);
                }
            } catch (IOException ignored) {
            }
        }, name);
        reader.setDaemon(true);
        return reader;
    }

    private void saveRootLog(List<String> lines, int exitCode) {
        File output = lastRootLog();
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(output, false), StandardCharsets.UTF_8))) {
            writer.write("boot_id=" + currentBootId());
            writer.newLine();
            writer.write("exit=" + exitCode);
            writer.newLine();
            synchronized (lines) {
                for (String line : lines) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            log("실행 로그 저장: " + output.getAbsolutePath());
        } catch (IOException e) {
            log("실행 로그 저장 실패: " + e.getMessage());
        }
    }

    private File nativeFile(String name) {
        return new File(context.getApplicationInfo().nativeLibraryDir, name);
    }

    private void status(String text, int color) {
        listener.onStatus(text, color);
    }

    private void log(String line) {
        listener.onLog(line);
    }

    private record SlideVerdict(long slide, String argument, int keeperPid) {
    }
}
