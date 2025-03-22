package checkcves.util;

import com.google.gson.Gson;
import httpclient.HttpCallRequest;
import httpclient.Serializers;

import java.net.http.HttpClient;

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

}
