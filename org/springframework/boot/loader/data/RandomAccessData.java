/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader.data;

import java.io.IOException;
import java.io.InputStream;

public interface RandomAccessData {
    public InputStream getInputStream() throws IOException;

    public RandomAccessData getSubsection(long var1, long var3);

    public byte[] read() throws IOException;

    public byte[] read(long var1, long var3) throws IOException;

    public long getSize();
}

