/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader.jar;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.lang.ref.SoftReference;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.boot.loader.jar.JarFile;
import org.springframework.boot.loader.jar.JarURLConnection;

public class Handler
extends URLStreamHandler {
    private static final String JAR_PROTOCOL = "jar:";
    private static final String FILE_PROTOCOL = "file:";
    private static final String SEPARATOR = "!/";
    private static final String CURRENT_DIR = "/./";
    private static final Pattern CURRENT_DIR_PATTERN = Pattern.compile("/./", 16);
    private static final String PARENT_DIR = "/../";
    private static final String[] FALLBACK_HANDLERS = new String[]{"sun.net.www.protocol.jar.Handler"};
    private static SoftReference<Map<File, JarFile>> rootFileCache = new SoftReference<Object>(null);
    private final JarFile jarFile;
    private URLStreamHandler fallbackHandler;

    public Handler() {
        this(null);
    }

    public Handler(JarFile jarFile) {
        this.jarFile = jarFile;
    }

    @Override
    protected URLConnection openConnection(URL url) throws IOException {
        if (this.jarFile != null && this.isUrlInJarFile(url, this.jarFile)) {
            return JarURLConnection.get(url, this.jarFile);
        }
        try {
            return JarURLConnection.get(url, this.getRootJarFileFromUrl(url));
        }
        catch (Exception ex) {
            return this.openFallbackConnection(url, ex);
        }
    }

    private boolean isUrlInJarFile(URL url, JarFile jarFile) throws MalformedURLException {
        return url.getPath().startsWith(jarFile.getUrl().getPath()) && url.toString().startsWith(jarFile.getUrlString());
    }

    private URLConnection openFallbackConnection(URL url, Exception reason) throws IOException {
        try {
            return this.openConnection(this.getFallbackHandler(), url);
        }
        catch (Exception ex) {
            if (reason instanceof IOException) {
                this.log(false, "Unable to open fallback handler", ex);
                throw (IOException)reason;
            }
            this.log(true, "Unable to open fallback handler", ex);
            if (reason instanceof RuntimeException) {
                throw (RuntimeException)reason;
            }
            throw new IllegalStateException(reason);
        }
    }

    private void log(boolean warning, String message, Exception cause) {
        block2 : {
            try {
                Level level = warning ? Level.WARNING : Level.FINEST;
                Logger.getLogger(this.getClass().getName()).log(level, message, cause);
            }
            catch (Exception ex) {
                if (!warning) break block2;
                System.err.println("WARNING: " + message);
            }
        }
    }

    private URLStreamHandler getFallbackHandler() {
        if (this.fallbackHandler != null) {
            return this.fallbackHandler;
        }
        for (String handlerClassName : FALLBACK_HANDLERS) {
            try {
                Class<?> handlerClass = Class.forName(handlerClassName);
                this.fallbackHandler = (URLStreamHandler)handlerClass.newInstance();
                return this.fallbackHandler;
            }
            catch (Exception handlerClass) {
            }
        }
        throw new IllegalStateException("Unable to find fallback handler");
    }

    private URLConnection openConnection(URLStreamHandler handler, URL url) throws Exception {
        return new URL(null, url.toExternalForm(), handler).openConnection();
    }

    @Override
    protected void parseURL(URL context, String spec, int start, int limit) {
        if (spec.regionMatches(true, 0, JAR_PROTOCOL, 0, JAR_PROTOCOL.length())) {
            this.setFile(context, this.getFileFromSpec(spec.substring(start, limit)));
        } else {
            this.setFile(context, this.getFileFromContext(context, spec.substring(start, limit)));
        }
    }

    private String getFileFromSpec(String spec) {
        int separatorIndex = spec.lastIndexOf(SEPARATOR);
        if (separatorIndex == -1) {
            throw new IllegalArgumentException("No !/ in spec '" + spec + "'");
        }
        try {
            new URL(spec.substring(0, separatorIndex));
            return spec;
        }
        catch (MalformedURLException ex) {
            throw new IllegalArgumentException("Invalid spec URL '" + spec + "'", ex);
        }
    }

    private String getFileFromContext(URL context, String spec) {
        String file = context.getFile();
        if (spec.startsWith("/")) {
            return this.trimToJarRoot(file) + SEPARATOR + spec.substring(1);
        }
        if (file.endsWith("/")) {
            return file + spec;
        }
        int lastSlashIndex = file.lastIndexOf(47);
        if (lastSlashIndex == -1) {
            throw new IllegalArgumentException("No / found in context URL's file '" + file + "'");
        }
        return file.substring(0, lastSlashIndex + 1) + spec;
    }

    private String trimToJarRoot(String file) {
        int lastSeparatorIndex = file.lastIndexOf(SEPARATOR);
        if (lastSeparatorIndex == -1) {
            throw new IllegalArgumentException("No !/ found in context URL's file '" + file + "'");
        }
        return file.substring(0, lastSeparatorIndex);
    }

    private void setFile(URL context, String file) {
        String path = this.normalize(file);
        String query = null;
        int queryIndex = path.lastIndexOf(63);
        if (queryIndex != -1) {
            query = path.substring(queryIndex + 1);
            path = path.substring(0, queryIndex);
        }
        this.setURL(context, JAR_PROTOCOL, null, -1, null, null, path, query, context.getRef());
    }

    private String normalize(String file) {
        if (!file.contains(CURRENT_DIR) && !file.contains(PARENT_DIR)) {
            return file;
        }
        int afterLastSeparatorIndex = file.lastIndexOf(SEPARATOR) + SEPARATOR.length();
        String afterSeparator = file.substring(afterLastSeparatorIndex);
        afterSeparator = this.replaceParentDir(afterSeparator);
        afterSeparator = this.replaceCurrentDir(afterSeparator);
        return file.substring(0, afterLastSeparatorIndex) + afterSeparator;
    }

    private String replaceParentDir(String file) {
        int parentDirIndex;
        while ((parentDirIndex = file.indexOf(PARENT_DIR)) >= 0) {
            int precedingSlashIndex = file.lastIndexOf(47, parentDirIndex - 1);
            if (precedingSlashIndex >= 0) {
                file = file.substring(0, precedingSlashIndex) + file.substring(parentDirIndex + 3);
                continue;
            }
            file = file.substring(parentDirIndex + 4);
        }
        return file;
    }

    private String replaceCurrentDir(String file) {
        return CURRENT_DIR_PATTERN.matcher(file).replaceAll("/");
    }

    @Override
    protected int hashCode(URL u) {
        return this.hashCode(u.getProtocol(), u.getFile());
    }

    private int hashCode(String protocol, String file) {
        int result = protocol != null ? protocol.hashCode() : 0;
        int separatorIndex = file.indexOf(SEPARATOR);
        if (separatorIndex == -1) {
            return result + file.hashCode();
        }
        String source = file.substring(0, separatorIndex);
        String entry = this.canonicalize(file.substring(separatorIndex + 2));
        try {
            result += new URL(source).hashCode();
        }
        catch (MalformedURLException ex) {
            result += source.hashCode();
        }
        return result += entry.hashCode();
    }

    @Override
    protected boolean sameFile(URL u1, URL u2) {
        String nested2;
        String canonical1;
        String canonical2;
        if (!u1.getProtocol().equals("jar") || !u2.getProtocol().equals("jar")) {
            return false;
        }
        int separator1 = u1.getFile().indexOf(SEPARATOR);
        int separator2 = u2.getFile().indexOf(SEPARATOR);
        if (separator1 == -1 || separator2 == -1) {
            return super.sameFile(u1, u2);
        }
        String nested1 = u1.getFile().substring(separator1 + SEPARATOR.length());
        if (!nested1.equals(nested2 = u2.getFile().substring(separator2 + SEPARATOR.length())) && !(canonical1 = this.canonicalize(nested1)).equals(canonical2 = this.canonicalize(nested2))) {
            return false;
        }
        String root1 = u1.getFile().substring(0, separator1);
        String root2 = u2.getFile().substring(0, separator2);
        try {
            return super.sameFile(new URL(root1), new URL(root2));
        }
        catch (MalformedURLException malformedURLException) {
            return super.sameFile(u1, u2);
        }
    }

    private String canonicalize(String path) {
        return path.replace(SEPARATOR, "/");
    }

    public JarFile getRootJarFileFromUrl(URL url) throws IOException {
        String spec = url.getFile();
        int separatorIndex = spec.indexOf(SEPARATOR);
        if (separatorIndex == -1) {
            throw new MalformedURLException("Jar URL does not contain !/ separator");
        }
        String name = spec.substring(0, separatorIndex);
        return this.getRootJarFile(name);
    }

    private JarFile getRootJarFile(String name) throws IOException {
        try {
            JarFile result;
            if (!name.startsWith(FILE_PROTOCOL)) {
                throw new IllegalStateException("Not a file URL");
            }
            File file = new File(URI.create(name));
            Map<File, JarFile> cache = rootFileCache.get();
            JarFile jarFile = result = cache != null ? cache.get(file) : null;
            if (result == null) {
                result = new JarFile(file);
                Handler.addToRootFileCache(file, result);
            }
            return result;
        }
        catch (Exception ex) {
            throw new IOException("Unable to open root Jar file '" + name + "'", ex);
        }
    }

    static void addToRootFileCache(File sourceFile, JarFile jarFile) {
        Map<File, JarFile> cache = rootFileCache.get();
        if (cache == null) {
            cache = new ConcurrentHashMap<File, JarFile>();
            rootFileCache = new SoftReference<Map<File, JarFile>>(cache);
        }
        cache.put(sourceFile, jarFile);
    }

    public static void setUseFastConnectionExceptions(boolean useFastConnectionExceptions) {
        JarURLConnection.setUseFastExceptions(useFastConnectionExceptions);
    }
}

