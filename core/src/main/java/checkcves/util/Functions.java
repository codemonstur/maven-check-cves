package checkcves.util;

import com.google.gson.Gson;
import httpclient.HttpCallRequest;
import httpclient.Serializers;

import java.net.http.HttpClient;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static httpclient.HeaderStrategy.SILENT_REMOVE_NULL_HEADERS;
import static java.lang.System.currentTimeMillis;
import static java.nio.charset.StandardCharsets.UTF_8;

public enum Functions {;

    private static final Gson gson = new Gson();

    private static final Serializers serializers = new Serializers.Builder()
        .json(new Serializers.Serializer() {
            public <U> U fromData(final byte[] data, final Class<U> clazz) {
                return gson.fromJson(new String(data, UTF_8), clazz);
            }
        })
        .build();

    public static HttpCallRequest newHttpCall(final HttpClient http) {
        return new HttpCallRequest(http, serializers, SILENT_REMOVE_NULL_HEADERS);
    }

    public static ThreadFactory daemonThreadFactory(final String prefix) {
        final var counter = new AtomicInteger();
        return task -> {
            final var thread = new Thread(task, prefix + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    public static <T> List<T> toSortedList(final Set<T> set, final Comparator<T> comparator) {
        return toSortedCopy(new ArrayList<>(set), comparator);
    }

    public static <T> List<T> toSortedCopy(final List<T> list, final Comparator<T> comparator) {
        final var sorted = new ArrayList<>(list);
        sorted.sort(comparator);
        return sorted;
    }

    public static String encodeHex(final byte[] data) {
        return HexFormat.of().formatHex(data);
    }
    public static byte[] sha256(final String data, final Charset charset) {
        return sha256(data.getBytes(charset));
    }
    public static byte[] sha256(final byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean isNewerThan(final Path path, final TimeUnit unit, final int duration) {
        return path.toFile().lastModified() > (currentTimeMillis() - unit.toMillis(duration));
    }
    public static boolean isNewerThan(final Path path, final Duration age) {
        return path.toFile().lastModified() > (currentTimeMillis() - age.toMillis());
    }

}
