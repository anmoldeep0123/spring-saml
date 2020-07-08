/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader.jar;

import java.io.IOException;
import org.springframework.boot.loader.data.RandomAccessData;
import org.springframework.boot.loader.jar.AsciiBytes;
import org.springframework.boot.loader.jar.Bytes;

class CentralDirectoryEndRecord {
    private static final int MINIMUM_SIZE = 22;
    private static final int MAXIMUM_COMMENT_LENGTH = 65535;
    private static final int ZIP64_MAGICCOUNT = 65535;
    private static final int MAXIMUM_SIZE = 65557;
    private static final int SIGNATURE = 101010256;
    private static final int COMMENT_LENGTH_OFFSET = 20;
    private static final int READ_BLOCK_SIZE = 256;
    private final Zip64End zip64End;
    private byte[] block;
    private int offset;
    private int size;

    CentralDirectoryEndRecord(RandomAccessData data) throws IOException {
        this.block = this.createBlockFromEndOfData(data, 256);
        this.size = 22;
        this.offset = this.block.length - this.size;
        while (!this.isValid()) {
            ++this.size;
            if (this.size > this.block.length) {
                if (this.size >= 65557 || (long)this.size > data.getSize()) {
                    throw new IOException("Unable to find ZIP central directory records after reading " + this.size + " bytes");
                }
                this.block = this.createBlockFromEndOfData(data, this.size + 256);
            }
            this.offset = this.block.length - this.size;
        }
        int startOfCentralDirectoryEndRecord = (int)(data.getSize() - (long)this.size);
        this.zip64End = this.isZip64() ? new Zip64End(data, startOfCentralDirectoryEndRecord) : null;
    }

    private byte[] createBlockFromEndOfData(RandomAccessData data, int size) throws IOException {
        int length = (int)Math.min(data.getSize(), (long)size);
        return data.read(data.getSize() - (long)length, length);
    }

    private boolean isValid() {
        if (this.block.length < 22 || Bytes.littleEndianValue(this.block, this.offset + 0, 4) != 101010256L) {
            return false;
        }
        long commentLength = Bytes.littleEndianValue(this.block, this.offset + 20, 2);
        return (long)this.size == 22L + commentLength;
    }

    private boolean isZip64() {
        return (int)Bytes.littleEndianValue(this.block, this.offset + 10, 2) == 65535;
    }

    long getStartOfArchive(RandomAccessData data) {
        long length = Bytes.littleEndianValue(this.block, this.offset + 12, 4);
        long specifiedOffset = Bytes.littleEndianValue(this.block, this.offset + 16, 4);
        long zip64EndSize = this.zip64End != null ? this.zip64End.getSize() : 0L;
        int zip64LocSize = this.zip64End != null ? 20 : 0;
        long actualOffset = data.getSize() - (long)this.size - length - zip64EndSize - (long)zip64LocSize;
        return actualOffset - specifiedOffset;
    }

    RandomAccessData getCentralDirectory(RandomAccessData data) {
        if (this.zip64End != null) {
            return this.zip64End.getCentralDirectory(data);
        }
        long offset = Bytes.littleEndianValue(this.block, this.offset + 16, 4);
        long length = Bytes.littleEndianValue(this.block, this.offset + 12, 4);
        return data.getSubsection(offset, length);
    }

    int getNumberOfRecords() {
        if (this.zip64End != null) {
            return this.zip64End.getNumberOfRecords();
        }
        long numberOfRecords = Bytes.littleEndianValue(this.block, this.offset + 10, 2);
        return (int)numberOfRecords;
    }

    String getComment() {
        int commentLength = (int)Bytes.littleEndianValue(this.block, this.offset + 20, 2);
        AsciiBytes comment = new AsciiBytes(this.block, this.offset + 20 + 2, commentLength);
        return comment.toString();
    }

    private static final class Zip64Locator {
        static final int ZIP64_LOCSIZE = 20;
        static final int ZIP64_LOCOFF = 8;
        private final long zip64EndOffset;
        private final int offset;

        private Zip64Locator(RandomAccessData data, int centralDirectoryEndOffset) throws IOException {
            this.offset = centralDirectoryEndOffset - 20;
            byte[] block = data.read(this.offset, 20L);
            this.zip64EndOffset = Bytes.littleEndianValue(block, 8, 8);
        }

        private long getZip64EndSize() {
            return (long)this.offset - this.zip64EndOffset;
        }

        private long getZip64EndOffset() {
            return this.zip64EndOffset;
        }
    }

    private static final class Zip64End {
        private static final int ZIP64_ENDTOT = 32;
        private static final int ZIP64_ENDSIZ = 40;
        private static final int ZIP64_ENDOFF = 48;
        private final Zip64Locator locator;
        private final long centralDirectoryOffset;
        private final long centralDirectoryLength;
        private int numberOfRecords;

        private Zip64End(RandomAccessData data, int centratDirectoryEndOffset) throws IOException {
            this(data, new Zip64Locator(data, centratDirectoryEndOffset));
        }

        private Zip64End(RandomAccessData data, Zip64Locator locator) throws IOException {
            this.locator = locator;
            byte[] block = data.read(locator.getZip64EndOffset(), 56L);
            this.centralDirectoryOffset = Bytes.littleEndianValue(block, 48, 8);
            this.centralDirectoryLength = Bytes.littleEndianValue(block, 40, 8);
            this.numberOfRecords = (int)Bytes.littleEndianValue(block, 32, 8);
        }

        private long getSize() {
            return this.locator.getZip64EndSize();
        }

        private RandomAccessData getCentralDirectory(RandomAccessData data) {
            return data.getSubsection(this.centralDirectoryOffset, this.centralDirectoryLength);
        }

        private int getNumberOfRecords() {
            return this.numberOfRecords;
        }
    }

}

