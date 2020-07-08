/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader.archive;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.util.jar.JarEntry;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import org.springframework.boot.loader.archive.Archive;
import org.springframework.boot.loader.jar.JarFile;

public class JarFileArchive
implements Archive {
    private static final String UNPACK_MARKER = "UNPACK:";
    private static final int BUFFER_SIZE = 32768;
    private final JarFile jarFile;
    private URL url;
    private File tempUnpackFolder;

    public JarFileArchive(File file) throws IOException {
        this(file, file.toURI().toURL());
    }

    public JarFileArchive(File file, URL url) throws IOException {
        this(new JarFile(file));
        this.url = url;
    }

    public JarFileArchive(JarFile jarFile) {
        this.jarFile = jarFile;
    }

    @Override
    public URL getUrl() throws MalformedURLException {
        if (this.url != null) {
            return this.url;
        }
        return this.jarFile.getUrl();
    }

    @Override
    public Manifest getManifest() throws IOException {
        return this.jarFile.getManifest();
    }

    @Override
    public List<Archive> getNestedArchives(Archive.EntryFilter filter) throws IOException {
        ArrayList<Archive> nestedArchives = new ArrayList<Archive>();
        for (Archive.Entry entry : this) {
            if (!filter.matches(entry)) continue;
            nestedArchives.add(this.getNestedArchive(entry));
        }
        return Collections.unmodifiableList(nestedArchives);
    }

    @Override
    public Iterator<Archive.Entry> iterator() {
        return new EntryIterator(this.jarFile.entries());
    }

    @Override
    public void close() throws IOException {
        this.jarFile.close();
    }

    protected Archive getNestedArchive(Archive.Entry entry) throws IOException {
        JarEntry jarEntry = ((JarFileEntry)entry).getJarEntry();
        if (jarEntry.getComment().startsWith(UNPACK_MARKER)) {
            return this.getUnpackedNestedArchive(jarEntry);
        }
        try {
            JarFile jarFile = this.jarFile.getNestedJarFile(jarEntry);
            return new JarFileArchive(jarFile);
        }
        catch (Exception ex) {
            throw new IllegalStateException("Failed to get nested archive for entry " + entry.getName(), ex);
        }
    }

    private Archive getUnpackedNestedArchive(JarEntry jarEntry) throws IOException {
        File file;
        String name = jarEntry.getName();
        if (name.lastIndexOf(47) != -1) {
            name = name.substring(name.lastIndexOf(47) + 1);
        }
        if (!(file = new File(this.getTempUnpackFolder(), name)).exists() || file.length() != jarEntry.getSize()) {
            this.unpack(jarEntry, file);
        }
        return new JarFileArchive(file, file.toURI().toURL());
    }

    private File getTempUnpackFolder() {
        if (this.tempUnpackFolder == null) {
            File tempFolder = new File(System.getProperty("java.io.tmpdir"));
            this.tempUnpackFolder = this.createUnpackFolder(tempFolder);
        }
        return this.tempUnpackFolder;
    }

    private File createUnpackFolder(File parent) {
        int attempts = 0;
        while (attempts++ < 1000) {
            String fileName = new File(this.jarFile.getName()).getName();
            File unpackFolder = new File(parent, fileName + "-spring-boot-libs-" + UUID.randomUUID());
            if (!unpackFolder.mkdirs()) continue;
            return unpackFolder;
        }
        throw new IllegalStateException("Failed to create unpack folder in directory '" + parent + "'");
    }

    private void unpack(JarEntry entry, File file) throws IOException {
        try (InputStream inputStream = this.jarFile.getInputStream(entry);
             FileOutputStream outputStream = new FileOutputStream(file);){
            int bytesRead;
            byte[] buffer = new byte[32768];
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                ((OutputStream)outputStream).write(buffer, 0, bytesRead);
            }
            outputStream.flush();
        }
    }

    public String toString() {
        try {
            return this.getUrl().toString();
        }
        catch (Exception ex) {
            return "jar archive";
        }
    }

    private static class JarFileEntry
    implements Archive.Entry {
        private final JarEntry jarEntry;

        JarFileEntry(JarEntry jarEntry) {
            this.jarEntry = jarEntry;
        }

        JarEntry getJarEntry() {
            return this.jarEntry;
        }

        @Override
        public boolean isDirectory() {
            return this.jarEntry.isDirectory();
        }

        @Override
        public String getName() {
            return this.jarEntry.getName();
        }
    }

    private static class EntryIterator
    implements Iterator<Archive.Entry> {
        private final Enumeration<JarEntry> enumeration;

        EntryIterator(Enumeration<JarEntry> enumeration) {
            this.enumeration = enumeration;
        }

        @Override
        public boolean hasNext() {
            return this.enumeration.hasMoreElements();
        }

        @Override
        public Archive.Entry next() {
            return new JarFileEntry(this.enumeration.nextElement());
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException("remove");
        }
    }

}

