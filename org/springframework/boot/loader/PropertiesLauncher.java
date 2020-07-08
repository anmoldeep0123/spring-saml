/*
 * Decompiled with CFR 0.146.
 * 
 * Could not load the following classes:
 *  org.springframework.util.Assert
 */
package org.springframework.boot.loader;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.jar.Attributes;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.boot.loader.LaunchedURLClassLoader;
import org.springframework.boot.loader.Launcher;
import org.springframework.boot.loader.archive.Archive;
import org.springframework.boot.loader.archive.ExplodedArchive;
import org.springframework.boot.loader.archive.JarFileArchive;
import org.springframework.boot.loader.util.SystemPropertyUtils;
import org.springframework.util.Assert;

public class PropertiesLauncher
extends Launcher {
    private static final Class<?>[] PARENT_ONLY_PARAMS = new Class[]{ClassLoader.class};
    private static final Class<?>[] URLS_AND_PARENT_PARAMS = new Class[]{URL[].class, ClassLoader.class};
    private static final Class<?>[] NO_PARAMS = new Class[0];
    private static final URL[] NO_URLS = new URL[0];
    private static final String DEBUG = "loader.debug";
    public static final String MAIN = "loader.main";
    public static final String PATH = "loader.path";
    public static final String HOME = "loader.home";
    public static final String ARGS = "loader.args";
    public static final String CONFIG_NAME = "loader.config.name";
    public static final String CONFIG_LOCATION = "loader.config.location";
    public static final String SET_SYSTEM_PROPERTIES = "loader.system";
    private static final Pattern WORD_SEPARATOR = Pattern.compile("\\W+");
    private static final String NESTED_ARCHIVE_SEPARATOR = "!" + File.separator;
    private final File home;
    private List<String> paths = new ArrayList<String>();
    private final Properties properties = new Properties();
    private Archive parent;

    public PropertiesLauncher() {
        try {
            this.home = this.getHomeDirectory();
            this.initializeProperties();
            this.initializePaths();
            this.parent = this.createArchive();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    protected File getHomeDirectory() {
        try {
            return new File(this.getPropertyWithDefault(HOME, "${user.dir}"));
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private void initializeProperties() throws Exception, IOException {
        ArrayList<String> configs = new ArrayList<String>();
        if (this.getProperty(CONFIG_LOCATION) != null) {
            configs.add(this.getProperty(CONFIG_LOCATION));
        } else {
            String[] names = this.getPropertyWithDefault(CONFIG_NAME, "loader").split(",");
            for (String name : names) {
                configs.add("file:" + this.getHomeDirectory() + "/" + name + ".properties");
                configs.add("classpath:" + name + ".properties");
                configs.add("classpath:BOOT-INF/classes/" + name + ".properties");
            }
        }
        for (String config : configs) {
            InputStream resource = this.getResource(config);
            Throwable throwable = null;
            try {
                if (resource != null) {
                    this.debug("Found: " + config);
                    this.loadResource(resource);
                    return;
                }
                this.debug("Not found: " + config);
            }
            catch (Throwable name) {
                throwable = name;
                throw name;
            }
            finally {
                if (resource == null) continue;
                if (throwable != null) {
                    try {
                        resource.close();
                    }
                    catch (Throwable name) {
                        throwable.addSuppressed(name);
                    }
                    continue;
                }
                resource.close();
            }
        }
    }

    private void loadResource(InputStream resource) throws IOException, Exception {
        this.properties.load(resource);
        for (Object key : Collections.list(this.properties.propertyNames())) {
            String text = this.properties.getProperty((String)key);
            String value = SystemPropertyUtils.resolvePlaceholders(this.properties, text);
            if (value == null) continue;
            this.properties.put(key, value);
        }
        if ("true".equals(this.getProperty(SET_SYSTEM_PROPERTIES))) {
            this.debug("Adding resolved properties to System properties");
            for (Object key : Collections.list(this.properties.propertyNames())) {
                String value = this.properties.getProperty((String)key);
                System.setProperty((String)key, value);
            }
        }
    }

    private InputStream getResource(String config) throws Exception {
        if (config.startsWith("classpath:")) {
            return this.getClasspathResource(config.substring("classpath:".length()));
        }
        if (this.isUrl(config = this.handleUrl(config))) {
            return this.getURLResource(config);
        }
        return this.getFileResource(config);
    }

    private String handleUrl(String path) throws UnsupportedEncodingException {
        if ((path.startsWith("jar:file:") || path.startsWith("file:")) && (path = URLDecoder.decode(path, "UTF-8")).startsWith("file:") && (path = path.substring("file:".length())).startsWith("//")) {
            path = path.substring(2);
        }
        return path;
    }

    private boolean isUrl(String config) {
        return config.contains("://");
    }

    private InputStream getClasspathResource(String config) {
        while (config.startsWith("/")) {
            config = config.substring(1);
        }
        config = "/" + config;
        this.debug("Trying classpath: " + config);
        return this.getClass().getResourceAsStream(config);
    }

    private InputStream getFileResource(String config) throws Exception {
        File file = new File(config);
        this.debug("Trying file: " + config);
        if (file.canRead()) {
            return new FileInputStream(file);
        }
        return null;
    }

    private InputStream getURLResource(String config) throws Exception {
        URL url = new URL(config);
        if (this.exists(url)) {
            URLConnection con = url.openConnection();
            try {
                return con.getInputStream();
            }
            catch (IOException ex) {
                if (con instanceof HttpURLConnection) {
                    ((HttpURLConnection)con).disconnect();
                }
                throw ex;
            }
        }
        return null;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private boolean exists(URL url) throws IOException {
        URLConnection connection = url.openConnection();
        try {
            connection.setUseCaches(connection.getClass().getSimpleName().startsWith("JNLP"));
            if (connection instanceof HttpURLConnection) {
                HttpURLConnection httpConnection = (HttpURLConnection)connection;
                httpConnection.setRequestMethod("HEAD");
                int responseCode = httpConnection.getResponseCode();
                if (responseCode == 200) {
                    boolean bl = true;
                    return bl;
                }
                if (responseCode == 404) {
                    boolean bl = false;
                    return bl;
                }
            }
            boolean httpConnection = connection.getContentLength() >= 0;
            return httpConnection;
        }
        finally {
            if (connection instanceof HttpURLConnection) {
                ((HttpURLConnection)connection).disconnect();
            }
        }
    }

    private void initializePaths() throws Exception {
        String path = this.getProperty(PATH);
        if (path != null) {
            this.paths = this.parsePathsProperty(path);
        }
        this.debug("Nested archive paths: " + this.paths);
    }

    private List<String> parsePathsProperty(String commaSeparatedPaths) {
        ArrayList<String> paths = new ArrayList<String>();
        for (String path : commaSeparatedPaths.split(",")) {
            path = "".equals(path = this.cleanupPath(path)) ? "/" : path;
            paths.add(path);
        }
        if (paths.isEmpty()) {
            paths.add("lib");
        }
        return paths;
    }

    protected String[] getArgs(String ... args) throws Exception {
        String loaderArgs = this.getProperty(ARGS);
        if (loaderArgs != null) {
            String[] defaultArgs = loaderArgs.split("\\s+");
            String[] additionalArgs = args;
            args = new String[defaultArgs.length + additionalArgs.length];
            System.arraycopy(defaultArgs, 0, args, 0, defaultArgs.length);
            System.arraycopy(additionalArgs, 0, args, defaultArgs.length, additionalArgs.length);
        }
        return args;
    }

    @Override
    protected String getMainClass() throws Exception {
        String mainClass = this.getProperty(MAIN, "Start-Class");
        if (mainClass == null) {
            throw new IllegalStateException("No 'loader.main' or 'Start-Class' specified");
        }
        return mainClass;
    }

    @Override
    protected ClassLoader createClassLoader(List<Archive> archives) throws Exception {
        LinkedHashSet<URL> urls = new LinkedHashSet<URL>(archives.size());
        for (Archive archive : archives) {
            urls.add(archive.getUrl());
        }
        ClassLoader loader = new LaunchedURLClassLoader(urls.toArray(NO_URLS), this.getClass().getClassLoader());
        this.debug("Classpath: " + urls);
        String customLoaderClassName = this.getProperty("loader.classLoader");
        if (customLoaderClassName != null) {
            loader = this.wrapWithCustomClassLoader(loader, customLoaderClassName);
            this.debug("Using custom class loader: " + customLoaderClassName);
        }
        return loader;
    }

    private ClassLoader wrapWithCustomClassLoader(ClassLoader parent, String className) throws Exception {
        Class<ClassLoader> type = Class.forName(className, true, parent);
        ClassLoader classLoader = this.newClassLoader(type, PARENT_ONLY_PARAMS, parent);
        if (classLoader == null) {
            classLoader = this.newClassLoader(type, URLS_AND_PARENT_PARAMS, NO_URLS, parent);
        }
        if (classLoader == null) {
            classLoader = this.newClassLoader(type, NO_PARAMS, new Object[0]);
        }
        Assert.notNull((Object)classLoader, (String)("Unable to create class loader for " + className));
        return classLoader;
    }

    private ClassLoader newClassLoader(Class<ClassLoader> loaderClass, Class<?>[] parameterTypes, Object ... initargs) throws Exception {
        try {
            Constructor<ClassLoader> constructor = loaderClass.getDeclaredConstructor(parameterTypes);
            constructor.setAccessible(true);
            return constructor.newInstance(initargs);
        }
        catch (NoSuchMethodException ex) {
            return null;
        }
    }

    private String getProperty(String propertyKey) throws Exception {
        return this.getProperty(propertyKey, null, null);
    }

    private String getProperty(String propertyKey, String manifestKey) throws Exception {
        return this.getProperty(propertyKey, manifestKey, null);
    }

    private String getPropertyWithDefault(String propertyKey, String defaultValue) throws Exception {
        return this.getProperty(propertyKey, null, defaultValue);
    }

    /*
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    private String getProperty(String propertyKey, String manifestKey, String defaultValue) throws Exception {
        String value;
        String string;
        block22 : {
            String property;
            if (manifestKey == null) {
                manifestKey = propertyKey.replace('.', '-');
                manifestKey = PropertiesLauncher.toCamelCase(manifestKey);
            }
            if ((property = SystemPropertyUtils.getProperty(propertyKey)) != null) {
                String value3 = SystemPropertyUtils.resolvePlaceholders(this.properties, property);
                this.debug("Property '" + propertyKey + "' from environment: " + value3);
                return value3;
            }
            if (this.properties.containsKey(propertyKey)) {
                String value4 = SystemPropertyUtils.resolvePlaceholders(this.properties, this.properties.getProperty(propertyKey));
                this.debug("Property '" + propertyKey + "' from properties: " + value4);
                return value4;
            }
            try {
                if (this.home == null) break block22;
                try (ExplodedArchive archive222 = new ExplodedArchive(this.home, false);){
                    String value2;
                    Manifest manifest2 = archive222.getManifest();
                    if (manifest2 != null && (value2 = manifest2.getMainAttributes().getValue(manifestKey)) != null) {
                        this.debug("Property '" + manifestKey + "' from home directory manifest: " + value2);
                        String string2 = SystemPropertyUtils.resolvePlaceholders(this.properties, value2);
                        return string2;
                    }
                }
            }
            catch (IllegalStateException archive222) {
                // empty catch block
            }
        }
        Manifest manifest = this.createArchive().getManifest();
        if (manifest != null && (value = manifest.getMainAttributes().getValue(manifestKey)) != null) {
            this.debug("Property '" + manifestKey + "' from archive manifest: " + value);
            return SystemPropertyUtils.resolvePlaceholders(this.properties, value);
        }
        if (defaultValue != null) {
            string = SystemPropertyUtils.resolvePlaceholders(this.properties, defaultValue);
            return string;
        }
        string = defaultValue;
        return string;
    }

    @Override
    protected List<Archive> getClassPathArchives() throws Exception {
        ArrayList<Archive> lib = new ArrayList<Archive>();
        for (String path : this.paths) {
            for (Archive archive : this.getClassPathArchives(path)) {
                if (archive instanceof ExplodedArchive) {
                    ArrayList<Archive> nested = new ArrayList<Archive>(archive.getNestedArchives(new ArchiveEntryFilter()));
                    nested.add(0, archive);
                    lib.addAll(nested);
                    continue;
                }
                lib.add(archive);
            }
        }
        this.addNestedEntries(lib);
        return lib;
    }

    private List<Archive> getClassPathArchives(String path) throws Exception {
        List<Archive> nestedArchives;
        Archive archive;
        String root = this.cleanupPath(this.handleUrl(path));
        ArrayList<Archive> lib = new ArrayList<Archive>();
        File file = new File(root);
        if (!"/".equals(root)) {
            if (!this.isAbsolutePath(root)) {
                file = new File(this.home, root);
            }
            if (file.isDirectory()) {
                this.debug("Adding classpath entries from " + file);
                archive = new ExplodedArchive(file, false);
                lib.add(archive);
            }
        }
        if ((archive = this.getArchive(file)) != null) {
            this.debug("Adding classpath entries from archive " + archive.getUrl() + root);
            lib.add(archive);
        }
        if ((nestedArchives = this.getNestedArchives(root)) != null) {
            this.debug("Adding classpath entries from nested " + root);
            lib.addAll(nestedArchives);
        }
        return lib;
    }

    private boolean isAbsolutePath(String root) {
        return root.contains(":") || root.startsWith("/");
    }

    private Archive getArchive(File file) throws IOException {
        if (this.isNestedArchivePath(file)) {
            return null;
        }
        String name = file.getName().toLowerCase(Locale.ENGLISH);
        if (name.endsWith(".jar") || name.endsWith(".zip")) {
            return new JarFileArchive(file);
        }
        return null;
    }

    private boolean isNestedArchivePath(File file) {
        return file.getPath().contains(NESTED_ARCHIVE_SEPARATOR);
    }

    private List<Archive> getNestedArchives(String path) throws Exception {
        File file;
        Archive parent = this.parent;
        String root = path;
        if (!root.equals("/") && root.startsWith("/") || parent.getUrl().equals(this.home.toURI().toURL())) {
            return null;
        }
        int index = root.indexOf(33);
        if (index != -1) {
            file = new File(this.home, root.substring(0, index));
            if (root.startsWith("jar:file:")) {
                file = new File(root.substring("jar:file:".length(), index));
            }
            parent = new JarFileArchive(file);
            root = root.substring(index + 1);
            while (root.startsWith("/")) {
                root = root.substring(1);
            }
        }
        if (root.endsWith(".jar") && (file = new File(this.home, root)).exists()) {
            parent = new JarFileArchive(file);
            root = "";
        }
        if (root.equals("/") || root.equals("./") || root.equals(".")) {
            root = "";
        }
        PrefixMatchingArchiveFilter filter = new PrefixMatchingArchiveFilter(root);
        ArrayList<Archive> archives = new ArrayList<Archive>(parent.getNestedArchives(filter));
        if (("".equals(root) || ".".equals(root)) && !path.endsWith(".jar") && parent != this.parent) {
            archives.add(parent);
        }
        return archives;
    }

    private void addNestedEntries(List<Archive> lib) {
        try {
            lib.addAll(this.parent.getNestedArchives(entry -> {
                if (entry.isDirectory()) {
                    return entry.getName().equals("BOOT-INF/classes/");
                }
                return entry.getName().startsWith("BOOT-INF/lib/");
            }));
        }
        catch (IOException iOException) {
            // empty catch block
        }
    }

    private String cleanupPath(String path) {
        String lowerCasePath;
        if ((path = path.trim()).startsWith("./")) {
            path = path.substring(2);
        }
        if ((lowerCasePath = path.toLowerCase(Locale.ENGLISH)).endsWith(".jar") || lowerCasePath.endsWith(".zip")) {
            return path;
        }
        if (path.endsWith("/*")) {
            path = path.substring(0, path.length() - 1);
        } else if (!path.endsWith("/") && !path.equals(".")) {
            path = path + "/";
        }
        return path;
    }

    public static void main(String[] args) throws Exception {
        PropertiesLauncher launcher = new PropertiesLauncher();
        args = launcher.getArgs(args);
        launcher.launch(args);
    }

    public static String toCamelCase(CharSequence string) {
        if (string == null) {
            return null;
        }
        StringBuilder builder = new StringBuilder();
        Matcher matcher = WORD_SEPARATOR.matcher(string);
        int pos = 0;
        while (matcher.find()) {
            builder.append(PropertiesLauncher.capitalize(string.subSequence(pos, matcher.end()).toString()));
            pos = matcher.end();
        }
        builder.append(PropertiesLauncher.capitalize(string.subSequence(pos, string.length()).toString()));
        return builder.toString();
    }

    private static String capitalize(String str) {
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }

    private void debug(String message) {
        if (Boolean.getBoolean(DEBUG)) {
            System.out.println(message);
        }
    }

    private static final class ArchiveEntryFilter
    implements Archive.EntryFilter {
        private static final String DOT_JAR = ".jar";
        private static final String DOT_ZIP = ".zip";

        private ArchiveEntryFilter() {
        }

        @Override
        public boolean matches(Archive.Entry entry) {
            return entry.getName().endsWith(DOT_JAR) || entry.getName().endsWith(DOT_ZIP);
        }
    }

    private static final class PrefixMatchingArchiveFilter
    implements Archive.EntryFilter {
        private final String prefix;
        private final ArchiveEntryFilter filter = new ArchiveEntryFilter();

        private PrefixMatchingArchiveFilter(String prefix) {
            this.prefix = prefix;
        }

        @Override
        public boolean matches(Archive.Entry entry) {
            if (entry.isDirectory()) {
                return entry.getName().equals(this.prefix);
            }
            return entry.getName().startsWith(this.prefix) && this.filter.matches(entry);
        }
    }

}

