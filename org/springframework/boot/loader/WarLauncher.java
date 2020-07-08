/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader;

import org.springframework.boot.loader.ExecutableArchiveLauncher;
import org.springframework.boot.loader.archive.Archive;

public class WarLauncher
extends ExecutableArchiveLauncher {
    private static final String WEB_INF = "WEB-INF/";
    private static final String WEB_INF_CLASSES = "WEB-INF/classes/";
    private static final String WEB_INF_LIB = "WEB-INF/lib/";
    private static final String WEB_INF_LIB_PROVIDED = "WEB-INF/lib-provided/";

    public WarLauncher() {
    }

    protected WarLauncher(Archive archive) {
        super(archive);
    }

    @Override
    public boolean isNestedArchive(Archive.Entry entry) {
        if (entry.isDirectory()) {
            return entry.getName().equals(WEB_INF_CLASSES);
        }
        return entry.getName().startsWith(WEB_INF_LIB) || entry.getName().startsWith(WEB_INF_LIB_PROVIDED);
    }

    public static void main(String[] args) throws Exception {
        new WarLauncher().launch(args);
    }
}

