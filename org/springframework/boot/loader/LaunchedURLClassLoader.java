/*
 * Decompiled with CFR 0.146.
 */
package org.springframework.boot.loader;

import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLConnection;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.util.Enumeration;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import org.springframework.boot.loader.jar.Handler;
import org.springframework.boot.loader.jar.JarFile;

public class LaunchedURLClassLoader
extends URLClassLoader {
    public LaunchedURLClassLoader(URL[] urls, ClassLoader parent) {
        super(urls, parent);
    }

    @Override
    public URL findResource(String name) {
        Handler.setUseFastConnectionExceptions(true);
        try {
            URL uRL = super.findResource(name);
            return uRL;
        }
        finally {
            Handler.setUseFastConnectionExceptions(false);
        }
    }

    @Override
    public Enumeration<URL> findResources(String name) throws IOException {
        Handler.setUseFastConnectionExceptions(true);
        try {
            UseFastConnectionExceptionsEnumeration useFastConnectionExceptionsEnumeration = new UseFastConnectionExceptionsEnumeration(super.findResources(name));
            return useFastConnectionExceptionsEnumeration;
        }
        finally {
            Handler.setUseFastConnectionExceptions(false);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        Handler.setUseFastConnectionExceptions(true);
        try {
            block5 : {
                try {
                    this.definePackageIfNecessary(name);
                }
                catch (IllegalArgumentException ex) {
                    if (this.getPackage(name) != null) break block5;
                    throw new AssertionError((Object)("Package " + name + " has already been defined but it could not be found"));
                }
            }
            Class<?> ex = super.loadClass(name, resolve);
            return ex;
        }
        finally {
            Handler.setUseFastConnectionExceptions(false);
        }
    }

    private void definePackageIfNecessary(String className) {
        block3 : {
            String packageName;
            int lastDot = className.lastIndexOf(46);
            if (lastDot >= 0 && this.getPackage(packageName = className.substring(0, lastDot)) == null) {
                try {
                    this.definePackage(className, packageName);
                }
                catch (IllegalArgumentException ex) {
                    if (this.getPackage(packageName) != null) break block3;
                    throw new AssertionError((Object)("Package " + packageName + " has already been defined but it could not be found"));
                }
            }
        }
    }

    private void definePackage(String className, String packageName) {
        try {
            AccessController.doPrivileged(() -> {
                String packageEntryName = packageName.replace('.', '/') + "/";
                String classEntryName = className.replace('.', '/') + ".class";
                for (URL url : this.getURLs()) {
                    try {
                        java.util.jar.JarFile jarFile;
                        URLConnection connection = url.openConnection();
                        if (!(connection instanceof JarURLConnection) || (jarFile = ((JarURLConnection)connection).getJarFile()).getEntry(classEntryName) == null || jarFile.getEntry(packageEntryName) == null || jarFile.getManifest() == null) continue;
                        this.definePackage(packageName, jarFile.getManifest(), url);
                        return null;
                    }
                    catch (IOException connection) {
                        // empty catch block
                    }
                }
                return null;
            }, AccessController.getContext());
        }
        catch (PrivilegedActionException privilegedActionException) {
            // empty catch block
        }
    }

    public void clearCache() {
        for (URL url : this.getURLs()) {
            try {
                URLConnection connection = url.openConnection();
                if (!(connection instanceof JarURLConnection)) continue;
                this.clearCache(connection);
            }
            catch (IOException connection) {
                // empty catch block
            }
        }
    }

    private void clearCache(URLConnection connection) throws IOException {
        java.util.jar.JarFile jarFile = ((JarURLConnection)connection).getJarFile();
        if (jarFile instanceof JarFile) {
            ((JarFile)jarFile).clearCache();
        }
    }

    static {
        ClassLoader.registerAsParallelCapable();
    }

    private static class UseFastConnectionExceptionsEnumeration
    implements Enumeration<URL> {
        private final Enumeration<URL> delegate;

        UseFastConnectionExceptionsEnumeration(Enumeration<URL> delegate) {
            this.delegate = delegate;
        }

        @Override
        public boolean hasMoreElements() {
            Handler.setUseFastConnectionExceptions(true);
            try {
                boolean bl = this.delegate.hasMoreElements();
                return bl;
            }
            finally {
                Handler.setUseFastConnectionExceptions(false);
            }
        }

        @Override
        public URL nextElement() {
            Handler.setUseFastConnectionExceptions(true);
            try {
                URL uRL = this.delegate.nextElement();
                return uRL;
            }
            finally {
                Handler.setUseFastConnectionExceptions(false);
            }
        }
    }

}

