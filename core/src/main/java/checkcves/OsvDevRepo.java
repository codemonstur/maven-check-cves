package checkcves;

import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.OsvdevResponseBody;
import checkcves.model.osvdev.Vulnerability;
import com.google.gson.Gson;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

import static checkcves.util.Functions.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.Files.isRegularFile;
import static java.nio.file.StandardCopyOption.ATOMIC_MOVE;
import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;
import static java.nio.file.StandardOpenOption.*;
import static java.time.Duration.ofSeconds;
import static java.util.Collections.emptyList;
import static java.util.concurrent.TimeUnit.SECONDS;

// curl -v https://api.osv.dev/v1/query -d '{"version":"1.27","package":{"name":"org.yaml:snakeyaml","ecosystem":"Maven"}}'
// curl -v https://api.osv.dev/v1/query -d '{"version":"1.15.3","package":{"name":"org.jsoup:jsoup","ecosystem":"Maven"}}'
public enum OsvDevRepo {;

    /** Configuration for the on-disk result cache. When offline the cache is the only data source. */
    public record CacheConfig(boolean offline, Path repoDir, Duration ttl) {}

    private static final Duration requestTimeout = ofSeconds(30);
    private static final HttpClient http = HttpClient.newBuilder().connectTimeout(requestTimeout).build();
    private static final ExecutorService executor = Executors.newCachedThreadPool(daemonThreadFactory("checkcves-http-"));
    private static final Gson gson = new Gson();

    public static List<Vulnerability> findVulnerabilities(final OsvdevRequestBody request, final CacheConfig config)
            throws IOException {
        final var requestBody = gson.toJson(request);
        final var cacheFile = config.repoDir().resolve(encodeHex(sha256(requestBody, UTF_8)));

        final var cachedVulns = readCache(cacheFile);
        if (cachedVulns != null && isNewerThan(cacheFile, config.ttl())) {
            return cachedVulns;
        }

        if (config.offline()) {
            if (cachedVulns != null) return cachedVulns;
            throw new IOException("No cached result available for " + request.pPackage().name() + ":" + request.version()
                    + " and the plugin is configured as offline");
        }

        try {
            final var vulns = queryVulnerabilities(requestBody);
            writeCache(config.repoDir(), cacheFile, vulns);
            return vulns;
        } catch (final IOException e) {
            if (cachedVulns != null) {
                return cachedVulns;
            }
            throw e;
        }
    }

    private static List<Vulnerability> queryVulnerabilities(final String requestBody) throws IOException {
        final var response = queryService(requestBody);
        if (response == null)
            throw new IOException("Invalid response received from the OSV service");
        // The OSV service omits the vulns field entirely when no vulnerabilities are known
        return response.vulns() == null ? emptyList() : response.vulns();
    }

    private static OsvdevResponseBody queryService(final String requestBody) throws IOException {
        final var future = executor.submit(() -> newHttpCall(http)
            .scheme("https").hostname("api.osv.dev")
            .post("/v1/query")
            .body(requestBody)
            .execute()
            .verifyNotServerError().verifySuccess()
            .fetchBodyInto(OsvdevResponseBody.class));
        try {
            return future.get(requestTimeout.toSeconds(), SECONDS);
        } catch (final InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while querying the OSV service", e);
        } catch (final TimeoutException e) {
            future.cancel(true);
            throw new IOException("Timed out querying the OSV service", e);
        } catch (final ExecutionException e) {
            if (e.getCause() instanceof IOException ioException) throw ioException;
            throw new IOException("Failed querying the OSV service", e.getCause());
        }
    }

    /**
     * Returns null when there is no usable cache entry: missing, unreadable, corrupt, or written in a
     * previous broken format. A corrupt entry is treated as a miss so the next query overwrites it.
     */
    private static List<Vulnerability> readCache(final Path cacheFile) {
        if (!isRegularFile(cacheFile)) return null;
        try {
            final var response = gson.fromJson(Files.readString(cacheFile, UTF_8), OsvdevResponseBody.class);
            if (response == null) return null;
            return response.vulns() == null ? emptyList() : response.vulns();
        } catch (final IOException | JsonParseException e) {
            return null;
        }
    }

    /**
     * Writes the cache entry atomically (temp file + move) so a concurrent or interrupted build can
     * never observe a partially written entry.
     */
    private static void writeCache(final Path repoDir, final Path cacheFile, final List<Vulnerability> vulns)
            throws IOException {
        Files.createDirectories(repoDir);
        final var tempFile = Files.createTempFile(repoDir, "query", ".tmp");
        try {
            Files.writeString(tempFile, gson.toJson(new OsvdevResponseBody(vulns)), CREATE, TRUNCATE_EXISTING);
            Files.move(tempFile, cacheFile, REPLACE_EXISTING, ATOMIC_MOVE);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

}
