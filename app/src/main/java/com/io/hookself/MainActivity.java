package com.io.hookself;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import android.os.Bundle;
import android.view.View;

import com.io.hookself.databinding.ActivityMainBinding;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

public class MainActivity extends AppCompatActivity {

    private static final int MAX_OUTPUT_CHARS = 64 * 1024;

    // Used to load the 'hookself' library on application startup.
    static {
        System.loadLibrary("hookself");
        System.loadLibrary("hookself_demo");
    }

    private ActivityMainBinding binding;
    private final ExecutorService actionExecutor = Executors.newSingleThreadExecutor();
    private boolean attached;
    private boolean busy;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());
        applySystemBarInsets();

        binding.attachSelf.setOnClickListener(view -> runDemoAction(
                R.string.demo_attaching, true, this::attachSelfForLogging));
        binding.openStatStatus.setOnClickListener(view -> runDemoAction(
                R.string.demo_running, false, this::openStatProcStatusForLogging));
        binding.ptraceCheck.setOnClickListener(view -> runDemoAction(
                R.string.demo_running, false, this::runPtraceDetectionForLogging));

        attached = isSelfAttachedForLogging();
        binding.sessionStatus.setText(attached
                ? R.string.demo_attached
                : R.string.demo_detached);
        updateControls();
    }

    private void applySystemBarInsets() {
        final int left = binding.getRoot().getPaddingLeft();
        final int top = binding.getRoot().getPaddingTop();
        final int right = binding.getRoot().getPaddingRight();
        final int bottom = binding.getRoot().getPaddingBottom();
        ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (view, windowInsets) -> {
            Insets systemBars = windowInsets.getInsets(
                    WindowInsetsCompat.Type.systemBars());
            view.setPadding(left + systemBars.left, top + systemBars.top,
                    right + systemBars.right, bottom + systemBars.bottom);
            return windowInsets;
        });
    }

    private void runDemoAction(int runningStatus, boolean attachAction,
            Supplier<String> action) {
        if (binding == null || busy) {
            return;
        }
        busy = true;
        binding.sessionStatus.setText(runningStatus);
        updateControls();

        actionExecutor.execute(() -> {
            String report;
            try {
                report = action.get();
                if (report == null) {
                    report = "HOOKSELF_UI_RESULT {\"verdict\":\"NULL_RESULT\"}";
                }
            } catch (RuntimeException error) {
                report = "HOOKSELF_UI_RESULT {\"verdict\":\"JAVA_ERROR\",\"type\":\""
                        + error.getClass().getSimpleName() + "\"}";
            }
            final String completedReport = report;
            final boolean runtimeAttached = isSelfAttachedForLogging();
            runOnUiThread(() -> {
                ActivityMainBinding current = binding;
                if (current == null || isFinishing() || isDestroyed()) {
                    return;
                }
                busy = false;
                attached = runtimeAttached;
                appendOutput(completedReport);
                current.sessionStatus.setText(attached
                        ? R.string.demo_attached
                        : attachAction
                                ? R.string.demo_attach_failed
                                : R.string.demo_detached);
                updateControls();
            });
        });
    }

    private void updateControls() {
        if (binding == null) {
            return;
        }
        binding.attachSelf.setEnabled(!busy && !attached);
        binding.openStatStatus.setEnabled(!busy && attached);
        binding.ptraceCheck.setEnabled(!busy && attached);
        binding.operationProgress.setVisibility(busy ? View.VISIBLE : View.GONE);
    }

    private void appendOutput(String report) {
        String existing = binding.logOutput.getText().toString();
        if (existing.equals(getString(R.string.demo_no_results))) {
            existing = "";
        }
        String output = existing.isEmpty() ? report : existing + "\n\n" + report;
        if (output.length() > MAX_OUTPUT_CHARS) {
            output = output.substring(output.length() - MAX_OUTPUT_CHARS);
        }
        binding.logOutput.setText(output);
        binding.logScroll.post(() -> binding.logScroll.fullScroll(View.FOCUS_DOWN));
    }

    @Override
    protected void onDestroy() {
        binding = null;
        actionExecutor.shutdownNow();
        super.onDestroy();
    }

    /**
     * A native method that is implemented by the 'hookself' native library,
     * which is packaged with this application.
     */
    public native boolean isSelfAttachedForLogging();

    public native String attachSelfForLogging();

    public native String openStatProcStatusForLogging();

    public native String runPtraceDetectionForLogging();
}
