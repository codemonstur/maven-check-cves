package checkcves;

import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.OsvdevResponseBody;
import checkcves.model.osvdev.Vulnerability;
import com.google.gson.Gson;

import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import static checkcves.util.Functions.*;
import static java.net.http.HttpClient.newHttpClient;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.isRegularFile;
import static java.nio.file.StandardOpenOption.*;
import static java.util.concurrent.TimeUnit.DAYS;

// curl -v https://api.osv.dev/v1/query -d '{"version":"1.27","package":{"name":"org.yaml:snakeyaml","ecosystem":"Maven"}}'
// curl -v https://api.osv.dev/v1/query -d '{"version":"1.15.3","package":{"name":"org.jsoup:jsoup","ecosystem":"Maven"}}'
public enum OsvDevRepo {;

    private static final Path repoDir = Paths.get(System.getProperty("user.home")).resolve(".osvdev-repo");

    private static final HttpClient http = newHttpClient();
    private static final Gson gson = new Gson();

    public static List<Vulnerability> findVulnerabilities(final OsvdevRequestBody request) throws IOException {
        final var requestBody = gson.toJson(request);
        final var cachedResponse = repoDir.resolve(encodeHex(sha256(requestBody, UTF_8)));

        if (isRegularFile(cachedResponse) && isNewerThan(cachedResponse, DAYS, 1)) {
            return gson.fromJson(Files.readString(cachedResponse, UTF_8), OsvdevResponseBody.class).vulns();
        }

        final var response = queryService(requestBody);
        Files.createDirectories(repoDir);
        Files.writeString(cachedResponse, gson.toJson(response), CREATE, TRUNCATE_EXISTING);
        return response.vulns();
    }

    private static OsvdevResponseBody queryService(final String requestBody) throws IOException {
        return newHttpCall(http, gson)
            .scheme("https").hostname("api.osv.dev")
            .post("/v1/query")
            .body(requestBody)
            .execute()
            .verifyNotServerError().verifySuccess()
            .fetchBodyInto(OsvdevResponseBody.class);
    }

}
