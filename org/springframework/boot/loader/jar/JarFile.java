/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader.jar;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.SoftReference;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLStreamHandler;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.function.Supplier;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import org.springframework.boot.loader.data.RandomAccessData;
import org.springframework.boot.loader.data.RandomAccessDataFile;
import org.springframework.boot.loader.jar.AsciiBytes;
import org.springframework.boot.loader.jar.CentralDirectoryEndRecord;
import org.springframework.boot.loader.jar.CentralDirectoryFileHeader;
import org.springframework.boot.loader.jar.CentralDirectoryParser;
import org.springframework.boot.loader.jar.CentralDirectoryVisitor;
import org.springframework.boot.loader.jar.FileHeader;
import org.springframework.boot.loader.jar.Handler;
import org.springframework.boot.loader.jar.JarEntry;
import org.springframework.boot.loader.jar.JarEntryFilter;
import org.springframework.boot.loader.jar.JarFileEntries;

public class JarFile
extends java.util.jar.JarFile {
    private static final String MANIFEST_NAME = "META-INF/MANIFEST.MF";
    private static final String PROTOCOL_HANDLER = "java.protocol.handler.pkgs";
    private static final String HANDLERS_PACKAGE = "org.springframework.boot.loader";
    private static final AsciiBytes META_INF = new AsciiBytes("META-INF/");
    private static final AsciiBytes SIGNATURE_FILE_EXTENSION = new AsciiBytes(".SF");
    private final RandomAccessDataFile rootFile;
    private final String pathFromRoot;
    private final RandomAccessData data;
    private final JarFileType type;
    private URL url;
    private String urlString;
    private JarFileEntries entries;
    private Supplier<Manifest> manifestSupplier;
    private SoftReference<Manifest> manifest;
    private boolean signed;
    private String comment;

    public JarFile(File file) throws IOException {
        this(new RandomAccessDataFile(file));
    }

    JarFile(RandomAccessDataFile file) throws IOException {
        this(file, "", file, JarFileType.DIRECT);
    }

    private JarFile(RandomAccessDataFile rootFile, String pathFromRoot, RandomAccessData data, JarFileType type) throws IOException {
        this(rootFile, pathFromRoot, data, null, type, null);
    }

    private JarFile(RandomAccessDataFile rootFile, String pathFromRoot, RandomAccessData data, JarEntryFilter filter, JarFileType type, Supplier<Manifest> manifestSupplier) throws IOException {
        super(rootFile.getFile());
        this.rootFile = rootFile;
        this.pathFromRoot = pathFromRoot;
        CentralDirectoryParser parser = new CentralDirectoryParser();
        this.entries = parser.addVisitor(new JarFileEntries(this, filter));
        this.type = type;
        parser.addVisitor(this.centralDirectoryVisitor());
        try {
            this.data = parser.parse(data, filter == null);
        }
        catch (RuntimeException ex) {
            this.close();
            throw ex;
        }
        this.manifestSupplier = manifestSupplier != null ? manifestSupplier : () -> {
            try {
                try (InputStream inputStream = this.getInputStream(MANIFEST_NAME);){
                    if (inputStream == null) {
                        Manifest manifest = null;
                        return manifest;
                    }
                    Manifest manifest = new Manifest(inputStream);
                    return manifest;
                }
            }
            catch (IOException ex) {
                throw new RuntimeException(ex);
            }
        };
    }

    private CentralDirectoryVisitor centralDirectoryVisitor() {
        return new CentralDirectoryVisitor(){

            @Override
            public void visitStart(CentralDirectoryEndRecord endRecord, RandomAccessData centralDirectoryData) {
                JarFile.this.comment = endRecord.getComment();
            }

            @Override
            public void visitFileHeader(CentralDirectoryFileHeader fileHeader, int dataOffset) {
                AsciiBytes name = fileHeader.getName();
                if (name.startsWith(META_INF) && name.endsWith(SIGNATURE_FILE_EXTENSION)) {
                    JarFile.this.signed = true;
                }
            }

            @Override
            public void visitEnd() {
            }
        };
    }

    protected final RandomAccessDataFile getRootJarFile() {
        return this.rootFile;
    }

    RandomAccessData getData() {
        return this.data;
    }

    @Override
    public Manifest getManifest() throws IOException {
        Manifest manifest;
        Manifest manifest2 = manifest = this.manifest != null ? this.manifest.get() : null;
        if (manifest == null) {
            try {
                manifest = this.manifestSupplier.get();
            }
            catch (RuntimeException ex) {
                throw new IOException(ex);
            }
            this.manifest = new SoftReference<Manifest>(manifest);
        }
        return manifest;
    }

    @Override
    public Enumeration<java.util.jar.JarEntry> entries() {
        final Iterator<JarEntry> iterator = this.entries.iterator();
        return new Enumeration<java.util.jar.JarEntry>(){

            @Override
            public boolean hasMoreElements() {
                return iterator.hasNext();
            }

            @Override
            public java.util.jar.JarEntry nextElement() {
                return (java.util.jar.JarEntry)iterator.next();
            }
        };
    }

    public JarEntry getJarEntry(CharSequence name) {
        return this.entries.getEntry(name);
    }

    @Override
    public JarEntry getJarEntry(String name) {
        return (JarEntry)this.getEntry(name);
    }

    public boolean containsEntry(String name) {
        return this.entries.containsEntry(name);
    }

    @Override
    public ZipEntry getEntry(String name) {
        return this.entries.getEntry(name);
    }

    @Override
    public synchronized InputStream getInputStream(ZipEntry entry) throws IOException {
        if (entry instanceof JarEntry) {
            return this.entries.getInputStream((JarEntry)entry);
        }
        return this.getInputStream(entry != null ? entry.getName() : null);
    }

    InputStream getInputStream(String name) throws IOException {
        return this.entries.getInputStream(name);
    }

    public synchronized JarFile getNestedJarFile(ZipEntry entry) throws IOException {
        return this.getNestedJarFile((JarEntry)entry);
    }

    public synchronized JarFile getNestedJarFile(JarEntry entry) throws IOException {
        try {
            return this.createJarFileFromEntry(entry);
        }
        catch (Exception ex) {
            throw new IOException("Unable to open nested jar file '" + entry.getName() + "'", ex);
        }
    }

    private JarFile createJarFileFromEntry(JarEntry entry) throws IOException {
        if (entry.isDirectory()) {
            return this.createJarFileFromDirectoryEntry(entry);
        }
        return this.createJarFileFromFileEntry(entry);
    }

    private JarFile createJarFileFromDirectoryEntry(JarEntry entry) throws IOException {
        AsciiBytes name = entry.getAsciiBytesName();
        JarEntryFilter filter = candidate -> {
            if (candidate.startsWith(name) && !candidate.equals(name)) {
                return candidate.substring(name.length());
            }
            return null;
        };
        return new JarFile(this.rootFile, this.pathFromRoot + "!/" + entry.getName().substring(0, name.length() - 1), this.data, filter, JarFileType.NESTED_DIRECTORY, this.manifestSupplier);
    }

    private JarFile createJarFileFromFileEntry(JarEntry entry) throws IOException {
        if (entry.getMethod() != 0) {
            throw new IllegalStateException("Unable to open nested entry '" + entry.getName() + "'. It has been compressed and nested jar files must be stored without compression. Please check the mechanism used to create your executable jar file");
        }
        RandomAccessData entryData = this.entries.getEntryData(entry.getName());
        return new JarFile(this.rootFile, this.pathFromRoot + "!/" + entry.getName(), entryData, JarFileType.NESTED_JAR);
    }

    @Override
    public String getComment() {
        return this.comment;
    }

    @Override
    public int size() {
        return this.entries.getSize();
    }

    @Override
    public void close() throws IOException {
        super.close();
        if (this.type == JarFileType.DIRECT) {
            this.rootFile.close();
        }
    }

    String getUrlString() throws MalformedURLException {
        if (this.urlString == null) {
            this.urlString = this.getUrl().toString();
        }
        return this.urlString;
    }

    public URL getUrl() throws MalformedURLException {
        if (this.url == null) {
            Handler handler = new Handler(this);
            String file = this.rootFile.getFile().toURI() + this.pathFromRoot + "!/";
            file = file.replace("file:////", "file://");
            this.url = new URL("jar", "", -1, file, handler);
        }
        return this.url;
    }

    public String toString() {
        return this.getName();
    }

    @Override
    public String getName() {
        return this.rootFile.getFile() + this.pathFromRoot;
    }

    boolean isSigned() {
        return this.signed;
    }

    void setupEntryCertificates(JarEntry entry) {
        try {
            try (JarInputStream inputStream = new JarInputStream(this.getData().getInputStream());){
                java.util.jar.JarEntry certEntry = inputStream.getNextJarEntry();
                while (certEntry != null) {
                    inputStream.closeEntry();
                    if (entry.getName().equals(certEntry.getName())) {
                        this.setCertificates(entry, certEntry);
                    }
                    this.setCertificates(this.getJarEntry(certEntry.getName()), certEntry);
                    certEntry = inputStream.getNextJarEntry();
                }
            }
        }
        catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void setCertificates(JarEntry entry, java.util.jar.JarEntry certEntry) {
        if (entry != null) {
            entry.setCertificates(certEntry);
        }
    }

    public void clearCache() {
        this.entries.clearCache();
    }

    protected String getPathFromRoot() {
        return this.pathFromRoot;
    }

    JarFileType getType() {
        return this.type;
    }

    public static void registerUrlProtocolHandler() {
        String handlers = System.getProperty(PROTOCOL_HANDLER, "");
        System.setProperty(PROTOCOL_HANDLER, "".equals(handlers) ? HANDLERS_PACKAGE : handlers + "|" + HANDLERS_PACKAGE);
        JarFile.resetCachedUrlHandlers();
    }

    private static void resetCachedUrlHandlers() {
        try {
            URL.setURLStreamHandlerFactory(null);
        }
        catch (Error error) {
            // empty catch block
        }
    }

    static enum JarFileType {
        DIRECT,
        NESTED_DIRECTORY,
        NESTED_JAR;
        
    }

}

