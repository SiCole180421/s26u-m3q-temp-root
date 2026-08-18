package dev.indevelopment.m3qroot;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Insets;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowManager;
import android.window.OnBackInvokedDispatcher;
import android.widget.TextView;
import android.text.method.ScrollingMovementMethod;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.card.MaterialCardView;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import rikka.shizuku.Shizuku;

public final class MainActivity extends AppCompatActivity {
    private static final int SHIZUKU_PERMISSION_REQUEST = 0x4d33;
    private static final String KSU_MANAGER_PACKAGE = "me.weishu.kernelsu";
    private static final String SHIZUKU_MANAGER_PACKAGE = "moe.shizuku.privileged.api";
    private static final int STATUS_SUCCESS = 0xff18753c;
    private static final int STATUS_WORKING = 0xff9a6700;
    private static final int STATUS_WARNING = 0xffb3261e;
    private static final int STATUS_NEUTRAL = 0xff5f6b76;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicBoolean shizukuPermissionPending = new AtomicBoolean();
    private final Shizuku.OnRequestPermissionResultListener shizukuPermissionListener =
            (requestCode, grantResult) -> {
                if (requestCode != SHIZUKU_PERMISSION_REQUEST) return;
                if (!shizukuPermissionPending.compareAndSet(true, false)) return;
                ui.post(() -> {
                    if (grantResult == PackageManager.PERMISSION_GRANTED) {
                        append("Shizuku shell 권한 승인 완료");
                        beginExploit(true);
                    } else {
                        abortPendingRun("Shizuku 권한이 거부되어 실행하지 않았습니다.");
                    }
                });
            };

    private M3qRootEngine engine;
    private MaterialCardView statusCard;
    private MaterialCardView diagnosticsCard;
    private TextView status;
    private TextView statusDetail;
    private TextView dashboard;
    private TextView log;
    private MaterialButton run;
    private MaterialButton reapplyModules;
    private MaterialButton restartZygote;
    private MaterialButton statusRefresh;
    private MaterialButton diagnosticsToggle;
    private boolean diagnosticsVisible;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        Shizuku.addRequestPermissionResultListener(shizukuPermissionListener);
        getWindow().setDecorFitsSystemWindows(false);
        setContentView(R.layout.activity_main);
        applySystemBarInsets(findViewById(R.id.page_scroll));
        bindViews();
        bindActions();
        getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
                OnBackInvokedDispatcher.PRIORITY_DEFAULT, () -> {
                    if (running.get()) {
                        append("커널 작업이 끝날 때까지 앱을 닫을 수 없습니다.");
                    } else {
                        finish();
                    }
                });

        engine = new M3qRootEngine(this, new M3qRootEngine.Listener() {
            @Override
            public void onStatus(String text, int color) {
                setStatus(text, color);
            }

            @Override
            public void onLog(String line) {
                append(line);
            }
        });

        append("==== device diagnostics ====");
        append("모델: " + Build.MODEL);
        append("커널: " + System.getProperty("os.version", "unknown"));
        append("펌웨어: " + Build.FINGERPRINT);

        if (!engine.isSupported()) {
            setStatus("지원되지 않는 펌웨어", STATUS_WARNING);
            setStatusDetail("이 앱은 SM-S948B AZG5 펌웨어에서만 실행할 수 있습니다.");
            run.setEnabled(false);
            append("정확한 SM-S948B AZG5 빌드에서만 실행할 수 있습니다.");
        } else {
            setStatus(getString(R.string.status_checking), STATUS_WORKING);
            setStatusDetail(getString(R.string.status_checking_detail));
        }
    }

    private void bindViews() {
        statusCard = findViewById(R.id.status_card);
        diagnosticsCard = findViewById(R.id.diagnostics_card);
        status = findViewById(R.id.status);
        statusDetail = findViewById(R.id.status_detail);
        dashboard = findViewById(R.id.dashboard);
        log = findViewById(R.id.log);
        log.setMovementMethod(new ScrollingMovementMethod());
        run = findViewById(R.id.run);
        reapplyModules = findViewById(R.id.reapply_modules);
        restartZygote = findViewById(R.id.restart_zygote);
        statusRefresh = findViewById(R.id.status_refresh);
        diagnosticsToggle = findViewById(R.id.diagnostics_toggle);
    }

    private static void applySystemBarInsets(View view) {
        int left = view.getPaddingLeft();
        int top = view.getPaddingTop();
        int right = view.getPaddingRight();
        int bottom = view.getPaddingBottom();
        view.setOnApplyWindowInsetsListener((target, windowInsets) -> {
            Insets bars = windowInsets.getInsets(
                    WindowInsets.Type.systemBars() | WindowInsets.Type.displayCutout());
            target.setPadding(left + bars.left, top + bars.top,
                    right + bars.right, bottom + bars.bottom);
            return windowInsets;
        });
        view.requestApplyInsets();
    }

    private void bindActions() {
        run.setOnClickListener(v -> onRunClicked());
        reapplyModules.setOnClickListener(v -> confirmModuleReload());
        restartZygote.setOnClickListener(v -> confirmSoftBoot());
        statusRefresh.setOnClickListener(v -> worker.execute(this::refreshRootState));
        findViewById(R.id.root_manager).setOnClickListener(v ->
                openPackage(KSU_MANAGER_PACKAGE,
                        "KernelSU Manager가 설치되어 있지 않습니다."));
        findViewById(R.id.shizuku_manager).setOnClickListener(v ->
                openPackage(SHIZUKU_MANAGER_PACKAGE,
                        "Shizuku Manager가 설치되어 있지 않습니다."));
        findViewById(R.id.share_log).setOnClickListener(v -> shareLastLog());
        diagnosticsToggle.setOnClickListener(v -> toggleDiagnostics());
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (engine != null && engine.isSupported() && !running.get()) {
            worker.execute(this::refreshRootState);
        }
    }

    private void toggleDiagnostics() {
        diagnosticsVisible = !diagnosticsVisible;
        diagnosticsCard.setVisibility(diagnosticsVisible ? View.VISIBLE : View.GONE);
        diagnosticsToggle.setText(diagnosticsVisible
                ? R.string.hide_diagnostics : R.string.show_diagnostics);
        if (diagnosticsVisible) {
            scrollLogToBottom();
        }
    }

    private void onRunClicked() {
        if (!running.compareAndSet(false, true)) return;
        worker.execute(() -> {
            M3qRootEngine.RootState current = engine.checkRoot(false);
            if (current.terminationUnconfirmed()) {
                finishUnconfirmedRun();
                return;
            }
            if (current.ready()) {
                finishRun(current);
                return;
            }
            if (current.bootstrap()) {
                append("bootstrap root 감지 · exploit 재실행 없이 KernelSU만 활성화합니다.");
                setStatus("KernelSU 활성화 중", STATUS_WORKING);
                setStatusDetail("커널 쓰기를 반복하지 않고 KernelSU 구성을 마무리합니다.");
                ui.post(this::lockUiForRun);
                int code = engine.activateKernelSu();
                append("KernelSU activation exit=" + code);
                if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                    finishUnconfirmedRun();
                    return;
                }
                finishRun(engine.checkRoot(true));
                return;
            }
            if (engine.hasAttemptedThisBoot()) {
                running.set(false);
                ui.post(() -> {
                    run.setVisibility(View.VISIBLE);
                    run.setEnabled(false);
                    setStatus("이번 부팅에서 이미 실행됨", STATUS_WARNING);
                    setStatusDetail("안전을 위해 재부팅 전에는 다시 실행할 수 없습니다.");
                    append("같은 boot ID의 재시도를 차단했습니다.");
                    renderDashboard(current);
                });
                return;
            }
            running.set(false);
            ui.post(this::confirmFreshRoot);
        });
    }

    private void confirmFreshRoot() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.root_dialog_title)
                .setMessage(R.string.root_dialog_message)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.root_dialog_confirm,
                        (dialog, which) -> startExploit())
                .show();
    }

    private void startExploit() {
        if (!running.compareAndSet(false, true)) return;
        lockUiForRun();
        append("==== fresh-root start ====");

        if (ShizukuShell.isRunning()) {
            int uid = ShizukuShell.uid();
            append("Shizuku 감지: uid=" + uid + " · tracefs fast path");
            if (!ShizukuShell.isGranted()) {
                setStatus("Shizuku 권한 승인 필요", STATUS_WORKING);
                setStatusDetail("표시되는 Shizuku 권한 요청을 승인하세요.");
                try {
                    shizukuPermissionPending.set(true);
                    Shizuku.requestPermission(SHIZUKU_PERMISSION_REQUEST);
                } catch (RuntimeException error) {
                    shizukuPermissionPending.set(false);
                    abortPendingRun("Shizuku 권한 요청 오류: " + error.getMessage());
                }
                return;
            }
            beginExploit(true);
            return;
        }

        append("Shizuku가 실행 중이 아니므로 exact Image physical-P0 경로를 사용합니다.");
        beginExploit(false);
    }

    private void beginExploit(boolean useShizuku) {
        long settleMillis = M3qRootEngine.bootSettleRemainingMillis();
        if (settleMillis > 0) {
            long settleSeconds = (settleMillis + 999) / 1000;
            abortPendingRun("부팅 직후 시스템 안정화를 위해 약 " + settleSeconds
                    + "초 후 다시 실행하세요. 이번 부팅의 시도 횟수는 소비하지 않았습니다.");
            return;
        }
        if (!engine.markAttemptForThisBoot()) {
            abortPendingRun("부팅 상태를 확인할 수 없어 커널 실행을 거부했습니다.");
            return;
        }
        setStatus("임시 루트 활성화 중", STATUS_WORKING);
        setStatusDetail(useShizuku
                ? "Shizuku 연결을 이용해 안전 조건을 확인하고 있습니다."
                : "기기 보안 상태를 확인한 뒤 임시 루트를 적용합니다.");
        worker.execute(() -> {
            int code = engine.runFreshRoot(useShizuku);
            append("fresh-root exit=" + code);
            if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                finishUnconfirmedRun();
                return;
            }
            finishRun(engine.checkRoot(true));
        });
    }

    private void confirmModuleReload() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.soft_root_dialog_title)
                .setMessage(R.string.soft_root_dialog_message)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.soft_root_dialog_confirm,
                        (dialog, which) -> startModuleReload())
                .show();
    }

    private void startModuleReload() {
        if (!running.compareAndSet(false, true)) return;
        lockUiForRun();
        setStatus("KernelSU 모듈 재로드 중", STATUS_WORKING);
        setStatusDetail("KernelSU 모듈 시작 단계를 다시 실행하고 있습니다.");
        append("==== KernelSU module reapply start ====");
        worker.execute(() -> {
            M3qRootEngine.RootState state = engine.checkRoot(false);
            if (!state.ready()) {
                append("KernelSU 임시 루트가 활성 상태가 아니어서 실행하지 않았습니다.");
                finishMaintenance(126, state, "", "");
                return;
            }
            int code = engine.reapplyKernelSuModules();
            append("module reapply exit=" + code);
            if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                finishUnconfirmedRun();
                return;
            }
            finishMaintenance(code, engine.checkRoot(false),
                    "모듈 재로드 완료",
                    "KernelSU 모듈이 다시 적용되었습니다. 이제 소프트 부팅을 진행하세요.");
        });
    }

    private void confirmSoftBoot() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.lsposed_dialog_title)
                .setMessage(R.string.lsposed_dialog_message)
                .setNegativeButton(R.string.cancel, null)
                .setPositiveButton(R.string.lsposed_dialog_confirm,
                        (dialog, which) -> startSoftBoot())
                .show();
    }

    private void startSoftBoot() {
        if (!running.compareAndSet(false, true)) return;
        lockUiForRun();
        setStatus("소프트 부팅 준비 중", STATUS_WORKING);
        setStatusDetail("Android 앱 환경(Zygote)을 다시 시작합니다.");
        append("Zygote 재시작을 요청합니다. 성공하면 이 앱도 종료됩니다.");
        worker.execute(() -> {
            M3qRootEngine.RootState state = engine.checkRoot(false);
            if (!state.ready()) {
                append("KernelSU 임시 루트가 활성 상태가 아니어서 실행하지 않았습니다.");
                finishMaintenance(126, state, "", "");
                return;
            }
            int code = engine.restartZygote();
            append("zygote restart exit=" + code);
            if (code == M3qRootEngine.EXIT_TERMINATION_UNCONFIRMED) {
                finishUnconfirmedRun();
                return;
            }
            finishMaintenance(code, engine.checkRoot(false),
                    "소프트 부팅 요청 완료",
                    "잠시 후 LSPosed 관리자에서 활성 상태를 확인하세요.");
        });
    }

    private void finishMaintenance(int code, M3qRootEngine.RootState state,
                                   String successText, String successDetail) {
        running.set(false);
        ui.post(() -> {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            statusRefresh.setEnabled(true);
            renderRootState(state);
            if (code == 0) {
                setStatus(successText, STATUS_SUCCESS);
                setStatusDetail(successDetail);
                return;
            }
            String reason = switch (code) {
                case 124 -> "작업 완료를 확인하지 못했습니다.";
                case 125 -> "KernelSU 구성 검증에 실패했습니다.";
                case 126 -> "KernelSU 루트 권한이 필요합니다.";
                default -> "명령 실행에 실패했습니다. code=" + code;
            };
            setStatus("작업 실패", STATUS_WARNING);
            setStatusDetail(reason + " 상태를 다시 확인하세요.");
        });
    }

    private void lockUiForRun() {
        run.setEnabled(false);
        reapplyModules.setEnabled(false);
        restartZygote.setEnabled(false);
        statusRefresh.setEnabled(false);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    private void abortPendingRun(String message) {
        append(message);
        running.set(false);
        ui.post(() -> {
            run.setVisibility(View.VISIBLE);
            run.setEnabled(engine.isSupported());
            reapplyModules.setEnabled(false);
            restartZygote.setEnabled(false);
            statusRefresh.setEnabled(true);
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            setStatus("실행하지 않음", STATUS_NEUTRAL);
            setStatusDetail(message);
        });
    }

    private void refreshRootState() {
        M3qRootEngine.RootState state = engine.checkRoot(false);
        ui.post(() -> renderRootState(state));
    }

    private void renderRootState(M3qRootEngine.RootState state) {
        if (state.terminationUnconfirmed()) {
            run.setVisibility(View.VISIBLE);
            setStatus("작업 상태 확인 불가", STATUS_WARNING);
            setStatusDetail("안전을 위해 기기를 재부팅한 뒤 다시 확인하세요.");
            run.setText(R.string.run_reboot_check);
            run.setEnabled(false);
        } else if (state.ready()) {
            setStatus("임시 루트 활성", STATUS_SUCCESS);
            setStatusDetail("KernelSU 3.2.5 · 재부팅 시 해제");
            run.setVisibility(View.GONE);
        } else if (state.bootstrap()) {
            run.setVisibility(View.VISIBLE);
            setStatus("루트 준비됨", STATUS_WORKING);
            setStatusDetail("KernelSU 활성화 단계만 남아 있습니다.");
            run.setText(R.string.run_kernel_su_activate);
            run.setEnabled(true);
        } else if (engine.hasAttemptedThisBoot()) {
            run.setVisibility(View.VISIBLE);
            setStatus("이번 부팅에서 이미 실행됨", STATUS_WARNING);
            setStatusDetail("안전을 위해 재부팅 전에는 다시 실행할 수 없습니다.");
            run.setText(R.string.run_reboot_retry);
            run.setEnabled(false);
        } else {
            run.setVisibility(View.VISIBLE);
            setStatus("임시 루트 비활성", STATUS_NEUTRAL);
            setStatusDetail("지원 기기 확인 완료 · 실행 준비");
            run.setText(R.string.root_activate);
            run.setEnabled(engine.isSupported());
        }
        boolean maintenanceReady = state.ready() && !running.get();
        reapplyModules.setEnabled(maintenanceReady);
        restartZygote.setEnabled(maintenanceReady);
        statusRefresh.setEnabled(!running.get());
        renderDashboard(state);
    }

    private void renderDashboard(M3qRootEngine.RootState state) {
        boolean shizukuRunning = ShizukuShell.isRunning();
        boolean shizukuGranted = ShizukuShell.isGranted();
        int shizukuUid = ShizukuShell.uid();
        String shizuku = !shizukuRunning ? "연결 안 됨"
                : !shizukuGranted ? "권한 승인 필요"
                : (shizukuUid == 2000 || shizukuUid == 0)
                ? "연결됨" : "권한 제한";
        String rootState = state.terminationUnconfirmed() ? "확인 필요"
                : state.ready() ? "활성"
                : state.bootstrap() ? "준비됨" : "비활성";
        String manager = getPackageManager().getLaunchIntentForPackage(
                KSU_MANAGER_PACKAGE) == null ? "설치 필요" : "설치됨";
        String attempted = engine.hasAttemptedThisBoot() ? "실행 완료" : "실행 전";
        dashboard.setText(getString(R.string.dashboard_format,
                engine.isSupported() ? "지원됨" : "지원 안 됨",
                shizuku, rootState, manager, attempted));
    }

    private void finishRun(M3qRootEngine.RootState state) {
        if (state.terminationUnconfirmed()) {
            finishUnconfirmedRun();
            return;
        }
        running.set(false);
        ui.post(() -> {
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            statusRefresh.setEnabled(true);
            if (state.ready()) {
                setStatus("임시 루트 활성", STATUS_SUCCESS);
                setStatusDetail("KernelSU 3.2.5 · 재부팅 시 해제");
                run.setVisibility(View.GONE);
                openPackage(KSU_MANAGER_PACKAGE,
                        "KernelSU Manager가 설치되어 있지 않습니다.");
            } else if (state.bootstrap()) {
                run.setVisibility(View.VISIBLE);
                setStatus("루트 준비됨", STATUS_WORKING);
                setStatusDetail("KernelSU 활성화를 다시 시도할 수 있습니다.");
                run.setText(R.string.run_kernel_su_reactivate);
                run.setEnabled(true);
            } else {
                run.setVisibility(View.VISIBLE);
                setStatus("임시 루트 활성화 실패", STATUS_WARNING);
                setStatusDetail("기기를 재부팅한 뒤 상태를 다시 확인하세요.");
                run.setEnabled(false);
            }
            reapplyModules.setEnabled(state.ready());
            restartZygote.setEnabled(state.ready());
            renderDashboard(state);
        });
    }

    private void finishUnconfirmedRun() {
        running.set(false);
        append("프로세스 제어가 끊겨 종료를 증명하지 못했습니다. 재부팅 전 재시도하지 마세요.");
        ui.post(() -> {
            run.setVisibility(View.VISIBLE);
            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
            setStatus("작업 상태 확인 불가", STATUS_WARNING);
            setStatusDetail("재부팅 전에는 같은 작업을 다시 실행하지 마세요.");
            run.setText(R.string.run_reboot_check);
            run.setEnabled(false);
            reapplyModules.setEnabled(false);
            restartZygote.setEnabled(false);
            statusRefresh.setEnabled(true);
        });
    }

    private void openPackage(String packageName, String missingMessage) {
        Intent launch = getPackageManager().getLaunchIntentForPackage(packageName);
        if (launch == null) {
            append(missingMessage);
            setStatus("관리 앱을 열 수 없음", STATUS_NEUTRAL);
            setStatusDetail(missingMessage);
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(launch);
    }

    private void shareLastLog() {
        File file = engine.lastRootLog();
        if (!file.isFile()) {
            append("공유할 실행 로그가 아직 없습니다.");
            setStatus("진단 보고서 없음", STATUS_NEUTRAL);
            setStatusDetail("임시 루트를 한 번 실행한 뒤 보고서를 만들 수 있습니다.");
            return;
        }
        try {
            String text = LogRedactor.redact(readLogTail(file));
            Intent share = new Intent(Intent.ACTION_SEND)
                    .setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, getString(R.string.share_subject))
                    .putExtra(Intent.EXTRA_TEXT, text);
            startActivity(Intent.createChooser(share, getString(R.string.share_chooser)));
        } catch (IOException error) {
            append("로그 읽기 실패: " + error.getMessage());
        }
    }

    private String readLogTail(File file) throws IOException {
        final int limit = 64 * 1024;
        try (RandomAccessFile input = new RandomAccessFile(file, "r")) {
            long skipped = Math.max(0, input.length() - limit);
            input.seek(skipped);
            byte[] bytes = new byte[(int) Math.min(limit, input.length())];
            input.readFully(bytes);
            String text = new String(bytes, StandardCharsets.UTF_8);
            if (skipped == 0) return text;
            return "[앞부분 및 절단된 첫 행 생략]\n"
                    + LogRedactor.dropPartialFirstLine(text);
        }
    }

    private void setStatus(String text, int semanticColor) {
        ui.post(() -> {
            int color = resolveStatusColor(semanticColor);
            status.setText(text);
            status.setTextColor(color);
            statusCard.setStrokeColor(color);
        });
    }

    private int resolveStatusColor(int semanticColor) {
        if (semanticColor == STATUS_SUCCESS) return getColor(R.color.m3q_success);
        if (semanticColor == STATUS_WORKING) return getColor(R.color.m3q_warning);
        if (semanticColor == STATUS_WARNING) return getColor(R.color.m3q_error);
        return getColor(R.color.m3q_neutral);
    }

    private void setStatusDetail(String text) {
        ui.post(() -> statusDetail.setText(text));
    }

    private void append(String line) {
        ui.post(() -> {
            log.append(line + "\n");
            if (diagnosticsVisible) {
                scrollLogToBottom();
            }
        });
    }

    private void scrollLogToBottom() {
        log.post(() -> {
            if (log.getLayout() == null) return;
            int scroll = log.getLayout().getLineTop(log.getLineCount())
                    - log.getHeight();
            log.scrollTo(0, Math.max(0, scroll));
        });
    }

    @Override
    protected void onDestroy() {
        Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener);
        worker.shutdown();
        super.onDestroy();
    }
}
