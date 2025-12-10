package com.toclone.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * UI flow
 *  1. user picks an input APK
 *  2. user chooses where to save the patched APK
 *  3. we copy  ·FridaLoader.dex  and  lib/*.so  from assets to cache
 *  4. ApkProcessor.injectFrida(…) does the heavy lifting
 */
public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";

    private Button   selectApkBtn, processApkBtn;
    private TextView selectedTxt , statusTxt;

    private Uri inputApkUri, outputApkUri;

    /* ---------------- document pickers ---------------- */

    private final ActivityResultLauncher<Intent> pickApk =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(),
                    res -> {
                        if (res.getResultCode() == Activity.RESULT_OK && res.getData() != null) {
                            inputApkUri = res.getData().getData();
                            if (inputApkUri != null) {
                                selectedTxt.setText("Selected: " + inputApkUri.getLastPathSegment());
                                processApkBtn.setEnabled(true);
                            }
                        }
                    });

    private final ActivityResultLauncher<Intent> createApk =
            registerForActivityResult(new ActivityResultContracts.StartActivityForResult(),
                    res -> {
                        if (res.getResultCode() == Activity.RESULT_OK && res.getData() != null) {
                            outputApkUri = res.getData().getData();
                            if (outputApkUri != null) {
                                statusTxt.setText("Processing …");
                                startProcessing();
                            }
                        }
                    });

    /* ---------------- lifecycle ---------------- */

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        setContentView(R.layout.activity_main);

        selectApkBtn = findViewById(R.id.selectApkButton);
        processApkBtn = findViewById(R.id.processApkButton);
        selectedTxt   = findViewById(R.id.selectedApkText);
        statusTxt     = findViewById(R.id.statusText);

        processApkBtn.setEnabled(false);

        selectApkBtn.setOnClickListener(v -> pickInput());
        processApkBtn.setOnClickListener(v -> pickOutput());
    }

    /* ---------------- UI helpers ---------------- */

    private void pickInput() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/vnd.android.package-archive");
        pickApk.launch(i);
    }

    private void pickOutput() {
        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/vnd.android.package-archive")
                .putExtra(Intent.EXTRA_TITLE, "patched.apk");
        createApk.launch(i);
    }

    /* ---------------- core logic ---------------- */

    private void startProcessing() {

        if (inputApkUri == null || outputApkUri == null) {
            Toast.makeText(this, "Pick input & output first", Toast.LENGTH_LONG).show();
            return;
        }

        try {
            /* ---- 1. copy FridaLoader.dex from assets → /cache ---- */
            File fridaDex = new File(getCacheDir(), "FridaLoader.dex");
            copyAsset("FridaLoader.dex", fridaDex);

            /* ---- 2. copy every *.so in  assets/lib/arm64-v8a/  ---- */
            File libOutDir = new File(getCacheDir(), "frida_libs");
            //noinspection ResultOfMethodCallIgnored
            libOutDir.mkdirs();

            String[] soFiles = getAssets().list("lib/arm64-v8a");   // returns {"libfrida-gadget.so", …}
            if (soFiles != null) {
                for (String file : soFiles) {
                    copyAsset("lib/arm64-v8a/" + file, new File(libOutDir, file));
                }
            }

            /* ---- 3. run ApkProcessor in a background thread ---- */
            ApkProcessor processor = new ApkProcessor(this);
            new Thread(() -> {
                try {
                    processor.injectFrida(inputApkUri, outputApkUri, fridaDex, libOutDir);
                    runOnUiThread(() -> {
                        statusTxt.setText("Done ✅");
                        Toast.makeText(this, "APK patched successfully!", Toast.LENGTH_LONG).show();
                    });
                } catch (IOException e) {
                    Log.e(TAG, "patch error", e);
                    runOnUiThread(() -> {
                        statusTxt.setText("Error: " + e.getMessage());
                        Toast.makeText(this, "Failed: " + e.getMessage(), Toast.LENGTH_LONG).show();
                    });
                }
            }).start();

        } catch (IOException e) {
            Log.e(TAG, "asset copy error", e);
            statusTxt.setText("Asset error: " + e.getMessage());
        }
    }

    /* ---------------- util ---------------- */

    private void copyAsset(String assetPath, File dst) throws IOException {
        try (InputStream in = getAssets().open(assetPath);
             OutputStream out = new FileOutputStream(dst)) {

            byte[] buf = new byte[8_192];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
    }
}
