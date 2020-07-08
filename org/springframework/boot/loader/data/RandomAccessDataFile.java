/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader.data;

import java.io.EOFException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import org.springframework.boot.loader.data.RandomAccessData;

public class RandomAccessDataFile
implements RandomAccessData {
    private final FileAccess fileAccess;
    private final long offset;
    private final long length;

    public RandomAccessDataFile(File file) {
        if (file == null) {
            throw new IllegalArgumentException("File must not be null");
        }
        this.fileAccess = new FileAccess(file);
        this.offset = 0L;
        this.length = file.length();
    }

    private RandomAccessDataFile(FileAccess fileAccess, long offset, long length) {
        this.fileAccess = fileAccess;
        this.offset = offset;
        this.length = length;
    }

    public File getFile() {
        return this.fileAccess.file;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return new DataInputStream();
    }

    @Override
    public RandomAccessData getSubsection(long offset, long length) {
        if (offset < 0L || length < 0L || offset + length > this.length) {
            throw new IndexOutOfBoundsException();
        }
        return new RandomAccessDataFile(this.fileAccess, this.offset + offset, length);
    }

    @Override
    public byte[] read() throws IOException {
        return this.read(0L, this.length);
    }

    @Override
    public byte[] read(long offset, long length) throws IOException {
        if (offset > this.length) {
            throw new IndexOutOfBoundsException();
        }
        if (offset + length > this.length) {
            throw new EOFException();
        }
        byte[] bytes = new byte[(int)length];
        this.read(bytes, offset, 0, bytes.length);
        return bytes;
    }

    private int readByte(long position) throws IOException {
        if (position >= this.length) {
            return -1;
        }
        return this.fileAccess.readByte(this.offset + position);
    }

    private int read(byte[] bytes, long position, int offset, int length) throws IOException {
        if (position > this.length) {
            return -1;
        }
        return this.fileAccess.read(bytes, this.offset + position, offset, length);
    }

    @Override
    public long getSize() {
        return this.length;
    }

    public void close() throws IOException {
        this.fileAccess.close();
    }

    private static final class FileAccess {
        private final Object monitor = new Object();
        private final File file;
        private RandomAccessFile randomAccessFile;

        private FileAccess(File file) {
            this.file = file;
            this.openIfNecessary();
        }

        /*
         * WARNING - Removed try catching itself - possible behaviour change.
         */
        private int read(byte[] bytes, long position, int offset, int length) throws IOException {
            Object object = this.monitor;
            synchronized (object) {
                this.openIfNecessary();
                this.randomAccessFile.seek(position);
                return this.randomAccessFile.read(bytes, offset, length);
            }
        }

        private void openIfNecessary() {
            if (this.randomAccessFile == null) {
                try {
                    this.randomAccessFile = new RandomAccessFile(this.file, "r");
                }
                catch (FileNotFoundException ex) {
                    throw new IllegalArgumentException(String.format("File %s must exist", this.file.getAbsolutePath()));
                }
            }
        }

        /*
         * WARNING - Removed try catching itself - possible behaviour change.
         */
        private void close() throws IOException {
            Object object = this.monitor;
            synchronized (object) {
                if (this.randomAccessFile != null) {
                    this.randomAccessFile.close();
                    this.randomAccessFile = null;
                }
            }
        }

        /*
         * WARNING - Removed try catching itself - possible behaviour change.
         */
        private int readByte(long position) throws IOException {
            Object object = this.monitor;
            synchronized (object) {
                this.openIfNecessary();
                this.randomAccessFile.seek(position);
                return this.randomAccessFile.read();
            }
        }
    }

    private class DataInputStream
    extends InputStream {
        private int position;

        private DataInputStream() {
        }

        @Override
        public int read() throws IOException {
            int read = RandomAccessDataFile.this.readByte(this.position);
            if (read > -1) {
                this.moveOn(1);
            }
            return read;
        }

        @Override
        public int read(byte[] b) throws IOException {
            return this.read(b, 0, b != null ? b.length : 0);
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (b == null) {
                throw new NullPointerException("Bytes must not be null");
            }
            return this.doRead(b, off, len);
        }

        int doRead(byte[] b, int off, int len) throws IOException {
            if (len == 0) {
                return 0;
            }
            int cappedLen = this.cap(len);
            if (cappedLen <= 0) {
                return -1;
            }
            return (int)this.moveOn(RandomAccessDataFile.this.read(b, this.position, off, cappedLen));
        }

        @Override
        public long skip(long n) throws IOException {
            return n <= 0L ? 0L : this.moveOn(this.cap(n));
        }

        private int cap(long n) {
            return (int)Math.min(RandomAccessDataFile.this.length - (long)this.position, n);
        }

        private long moveOn(int amount) {
            this.position += amount;
            return amount;
        }
    }

}

