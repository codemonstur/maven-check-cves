package checkcves.util;

import checkcves.model.Compliant;
import checkcves.model.Violation;
import com.google.gson.Gson;
import httpclient.HttpCallRequest;
import httpclient.Serializers;

import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

import static httpclient.HeaderStrategy.SILENT_REMOVE_NULL_HEADERS;
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

}
