package com.toclone.app;

import android.content.Context;
import android.net.Uri;
import android.util.Log;

import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import com.reandroid.arsc.chunk.xml.ResXmlDocument;
import com.reandroid.arsc.chunk.xml.ResXmlElement;
import com.reandroid.arsc.value.ValueType;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * 1. extracts input APK
 * 2. injects Frida provider
 * 3. copies bootstrap dex to next free classes{N}.dex
 * 4. copies every *.so from fridaLibDir to every ABI dir found in the APK
 * 5. repacks to outApk (unsigned)
 */
public class ApkProcessor {

    private static final String TAG = "ApkProcessor";
    private static final String ANDROID_MANIFEST = "AndroidManifest.xml";

    /* names */
    private static final String E_MANIFEST   = "manifest";
    private static final String E_APPLICATION = "application";
    private static final String E_PROVIDER   = "provider";

    private static final String A_PACKAGE     = "package";
    private static final String A_NAME        = "name";
    private static final String A_AUTHORITIES = "authorities";
    private static final String A_EXPORTED    = "exported";
    private static final String A_INIT_ORDER  = "initOrder";

    /* android attr ids */
    private static final int ID_ANDROID_NAME        = 0x01010003;
    private static final int ID_ANDROID_AUTHORITIES = 0x01010018;
    private static final int ID_ANDROID_EXPORTED    = 0x0101001e;
    private static final int ID_ANDROID_INIT_ORDER  = 0x01010427;

    /* regex */
    private static final Pattern SIG_PATH = Pattern.compile(
            "^META-INF/((.+)\\.(RSA|DSA|SF)|MANIFEST\\.MF)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern DEX_NAME = Pattern.compile(
            "^classes(\\d*)\\.dex$", Pattern.CASE_INSENSITIVE);

    private final Context ctx;

    public ApkProcessor(Context ctx) {
        this.ctx = ctx.getApplicationContext();
    }

    /* ------------------------------------------------------------------ */
    public void injectFrida(Uri inApk,
                            Uri outApk,
                            File fridaDex,
                            File fridaLibDir) throws IOException {

        File tmp = new File(ctx.getCacheDir(), "apk_" + System.currentTimeMillis());
        if (!tmp.mkdirs()) throw new IOException("mkdir failed: " + tmp);

        Set<Integer> dexNumbers = new HashSet<>();
        Set<String>  abiDirs    = new HashSet<>();
        byte[] manifestRaw      = null;

        /* -------- 1. unzip (strip META-INF) -------- */
        try (InputStream is = ctx.getContentResolver().openInputStream(inApk);
             ZipInputStream zis = new ZipInputStream(new BufferedInputStream(is))) {

            ZipEntry ze;
            while ((ze = zis.getNextEntry()) != null) {
                String name = ze.getName();
                if (name == null || name.isEmpty()) continue;
                if (SIG_PATH.matcher(name).matches()) continue;

                // record ABI folders
                if (name.startsWith("lib/") && name.endsWith(".so")) {
                    int slash = name.indexOf('/', 4);  // after "lib/"
                    if (slash > 0) abiDirs.add(name.substring(0, slash + 1));
                }

                // record dex indices
                Matcher m = DEX_NAME.matcher(name);
                if (m.matches()) {
                    int idx = m.group(1).isEmpty() ? 1 : Integer.parseInt(m.group(1)) + 1;
                    dexNumbers.add(idx);
                }

                File out = new File(tmp, name);
                if (ze.isDirectory()) {
                    out.mkdirs();
                    continue;
                }
                out.getParentFile().mkdirs();

                if (ANDROID_MANIFEST.equals(name)) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    copyStream(zis, baos);
                    manifestRaw = baos.toByteArray();
                } else {
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        copyStream(zis, fos);
                    }
                }
            }
        }

        if (manifestRaw == null) {
            deleteRec(tmp);
            throw new IOException("AndroidManifest.xml not found");
        }

        /* -------- 2. patch manifest -------- */
        byte[] patchedManifest = patchManifest(manifestRaw);

        /* -------- 3. add dex -------- */
        int nextIdx = dexNumbers.isEmpty() ? 2 : Collections.max(dexNumbers) + 1;
        String dexName = (nextIdx == 1)
                ? "classes.dex"
                : (nextIdx == 2 ? "classes2.dex" : "classes" + (nextIdx - 1) + ".dex");
        Files.copy(fridaDex.toPath(), new File(tmp, dexName).toPath(),
                StandardCopyOption.REPLACE_EXISTING);

        /* -------- 4. add native libs -------- */
        if (abiDirs.isEmpty()) abiDirs.add("lib/arm64-v8a/");

        File[] soFiles = fridaLibDir.listFiles((dir, n) -> n.endsWith(".so"));
        if (soFiles != null) {
            for (String abi : abiDirs) {
                File dstDir = new File(tmp, abi);
                dstDir.mkdirs();
                for (File so : soFiles) {
                    Files.copy(so.toPath(),
                               new File(dstDir, so.getName()).toPath(),
                               StandardCopyOption.REPLACE_EXISTING);
                }
            }
        }

        /* -------- 5. re-zip (unsigned) -------- */
        zipDir(tmp, outApk, patchedManifest);
        deleteRec(tmp);
    }

    /* ================= manifest helper ================= */
    private byte[] patchManifest(byte[] raw) throws IOException {
        ResXmlDocument doc = new ResXmlDocument();
        doc.readBytes(new ByteArrayInputStream(raw));

        ResXmlElement root = doc.getDocumentElement();
        if (root == null || !E_MANIFEST.equals(root.getName()))
            throw new IOException("no <manifest> root");

        ResXmlAttribute pkgAttr = root.searchAttributeByName(A_PACKAGE);
        if (pkgAttr == null) throw new IOException("package attr missing");
        String pkg = pkgAttr.getValueAsString();

        String authString = pkg + ".aurora.code.fridaloaderprovider";

        ResXmlElement app = root.getElement(E_APPLICATION);
        if (app == null) throw new IOException("<application> missing");

        /* skip if already injected */
        for (ResXmlElement p : app.listElements(E_PROVIDER)) {
            ResXmlAttribute a = p.searchAttributeByResourceId(ID_ANDROID_AUTHORITIES);
            if (a != null && authString.equals(a.getValueAsString())) {
                return raw;   // already contains provider
            }
        }

        ResXmlElement prov = app.newElement(E_PROVIDER);

        ResXmlAttribute nameAttr =
                prov.getOrCreateAndroidAttribute(A_NAME, ID_ANDROID_NAME);
        nameAttr.setValueAsString("aurora.code.FridaLoaderProvider");
        nameAttr.setValueType(ValueType.STRING);

        ResXmlAttribute authAttr =
                prov.getOrCreateAndroidAttribute(A_AUTHORITIES, ID_ANDROID_AUTHORITIES);
        authAttr.setValueAsString(authString);
        authAttr.setValueType(ValueType.STRING);

        ResXmlAttribute expAttr =
                prov.getOrCreateAndroidAttribute(A_EXPORTED, ID_ANDROID_EXPORTED);
        expAttr.setValueAsBoolean(true);
        expAttr.setValueType(ValueType.BOOLEAN);

        ResXmlAttribute orderAttr =
                prov.getOrCreateAndroidAttribute(A_INIT_ORDER, ID_ANDROID_INIT_ORDER);
        orderAttr.setData(0x7fffffff);
        orderAttr.setValueType(ValueType.DEC);

        doc.refresh();
        return doc.getBytes();
    }

    /* ================= zipping helper ================= */
    private void zipDir(File root, Uri outUri, byte[] manifestBytes)
            throws IOException {

        try (OutputStream os = ctx.getContentResolver().openOutputStream(outUri);
             ZipOutputStream zos = new ZipOutputStream(new BufferedOutputStream(os))) {

            zos.putNextEntry(new ZipEntry(ANDROID_MANIFEST));
            zos.write(manifestBytes);
            zos.closeEntry();

            addRec(root, root.getAbsolutePath(), zos);
        }
    }

    private void addRec(File node, String base, ZipOutputStream zos)
            throws IOException {

        if (node.isDirectory()) {
            File[] kids = node.listFiles();
            if (kids != null) for (File k : kids) addRec(k, base, zos);
            return;
        }

        String rel = node.getAbsolutePath()
                         .substring(base.length() + 1)
                         .replace(File.separatorChar, '/');
        if (ANDROID_MANIFEST.equals(rel)) return;

        zos.putNextEntry(new ZipEntry(rel));
        try (FileInputStream fis = new FileInputStream(node)) {
            copyStream(fis, zos);
        }
        zos.closeEntry();
    }

    /* ================= misc utils ================= */
    private static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
    }

    private static void deleteRec(File f) {
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) for (File k : kids) deleteRec(k);
        }
        // ignore result
        f.delete();
    }
}
