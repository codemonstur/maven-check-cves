package checkcves.util;

import com.google.gson.Gson;
import httpclient.HttpCallRequest;
import httpclient.Serializers;

import java.net.http.HttpClient;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static httpclient.HeaderStrategy.SILENT_REMOVE_NULL_HEADERS;
import static java.lang.System.currentTimeMillis;
import static java.nio.charset.StandardCharsets.UTF_8;

public enum Functions {;

    public static HttpCallRequest newHttpCall(final HttpClient http, final Gson gson) {
        final var serializers = new Serializers.Builder()
            .json(new Serializers.Serializer() {
                public <U> U fromData(final byte[] data, final Class<U> clazz) {
                    return gson.fromJson(new String(data, UTF_8), clazz);
                }
            })
            .build();

        return new HttpCallRequest(http, serializers, SILENT_REMOVE_NULL_HEADERS);
    }

    public static <T> List<T> toSortedList(final Set<T> set, final Comparator<T> comparator) {
        final var list = new ArrayList<T>(set);
        list.sort(comparator);
        return list;
    }

    public static String encodeHex(final byte[] data) {
        return Base64.getEncoder().encodeToString(data);
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

}
