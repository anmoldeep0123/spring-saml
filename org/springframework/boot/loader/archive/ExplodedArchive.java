/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader.archive;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.jar.Manifest;
import org.springframework.boot.loader.archive.Archive;
import org.springframework.boot.loader.archive.JarFileArchive;

public class ExplodedArchive
implements Archive {
    private static final Set<String> SKIPPED_NAMES = new HashSet<String>(Arrays.asList(".", ".."));
    private final File root;
    private final boolean recursive;
    private File manifestFile;
    private Manifest manifest;

    public ExplodedArchive(File root) {
        this(root, true);
    }

    public ExplodedArchive(File root, boolean recursive) {
        if (!root.exists() || !root.isDirectory()) {
            throw new IllegalArgumentException("Invalid source folder " + root);
        }
        this.root = root;
        this.recursive = recursive;
        this.manifestFile = this.getManifestFile(root);
    }

    private File getManifestFile(File root) {
        File metaInf = new File(root, "META-INF");
        return new File(metaInf, "MANIFEST.MF");
    }

    @Override
    public URL getUrl() throws MalformedURLException {
        return this.root.toURI().toURL();
    }

    @Override
    public Manifest getManifest() throws IOException {
        if (this.manifest == null && this.manifestFile.exists()) {
            try (FileInputStream inputStream = new FileInputStream(this.manifestFile);){
                this.manifest = new Manifest(inputStream);
            }
        }
        return this.manifest;
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
        return new FileEntryIterator(this.root, this.recursive);
    }

    protected Archive getNestedArchive(Archive.Entry entry) throws IOException {
        File file = ((FileEntry)entry).getFile();
        return file.isDirectory() ? new ExplodedArchive(file) : new JarFileArchive(file);
    }

    public String toString() {
        try {
            return this.getUrl().toString();
        }
        catch (Exception ex) {
            return "exploded archive";
        }
    }

    private static class FileEntry
    implements Archive.Entry {
        private final String name;
        private final File file;

        FileEntry(String name, File file) {
            this.name = name;
            this.file = file;
        }

        File getFile() {
            return this.file;
        }

        @Override
        public boolean isDirectory() {
            return this.file.isDirectory();
        }

        @Override
        public String getName() {
            return this.name;
        }
    }

    private static class FileEntryIterator
    implements Iterator<Archive.Entry> {
        private final Comparator<File> entryComparator = new EntryComparator();
        private final File root;
        private final boolean recursive;
        private final Deque<Iterator<File>> stack = new LinkedList<Iterator<File>>();
        private File current;

        FileEntryIterator(File root, boolean recursive) {
            this.root = root;
            this.recursive = recursive;
            this.stack.add(this.listFiles(root));
            this.current = this.poll();
        }

        @Override
        public boolean hasNext() {
            return this.current != null;
        }

        @Override
        public Archive.Entry next() {
            if (this.current == null) {
                throw new NoSuchElementException();
            }
            File file = this.current;
            if (file.isDirectory() && (this.recursive || file.getParentFile().equals(this.root))) {
                this.stack.addFirst(this.listFiles(file));
            }
            this.current = this.poll();
            String name = file.toURI().getPath().substring(this.root.toURI().getPath().length());
            return new FileEntry(name, file);
        }

        private Iterator<File> listFiles(File file) {
            File[] files = file.listFiles();
            if (files == null) {
                return Collections.emptyIterator();
            }
            Arrays.sort(files, this.entryComparator);
            return Arrays.asList(files).iterator();
        }

        private File poll() {
            while (!this.stack.isEmpty()) {
                while (this.stack.peek().hasNext()) {
                    File file = this.stack.peek().next();
                    if (SKIPPED_NAMES.contains(file.getName())) continue;
                    return file;
                }
                this.stack.poll();
            }
            return null;
        }

        @Override
        public void remove() {
            throw new UnsupportedOperationException("remove");
        }

        private static class EntryComparator
        implements Comparator<File> {
            private EntryComparator() {
            }

            @Override
            public int compare(File o1, File o2) {
                return o1.getAbsolutePath().compareTo(o2.getAbsolutePath());
            }
        }

    }

}

