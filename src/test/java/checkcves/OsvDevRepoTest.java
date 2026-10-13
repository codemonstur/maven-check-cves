package checkcves;

import checkcves.OsvDevRepo.CacheConfig;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.PPackage;
import com.google.gson.Gson;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;

import static checkcves.OsvDevRepo.findVulnerabilities;
import static checkcves.util.Functions.encodeHex;
import static checkcves.util.Functions.sha256;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.time.Duration.ofHours;
import static org.junit.jupiter.api.Assertions.*;

public final class OsvDevRepoTest {

    @TempDir
    Path cacheDir;

    private static final Gson gson = new Gson();

    @Test
    public void offlineReturnsFreshCachedResult() throws Exception {
        writeCache("{\"vulns\":[{\"id\":\"GHSA-test\"}]}");

        final var vulns = findVulnerabilities(request(), offlineConfig());

        assertEquals(1, vulns.size());
        assertEquals("GHSA-test", vulns.get(0).id());
    }

    @Test
    public void offlineUsesStaleCacheRatherThanFailing() throws Exception {
        writeCache("{\"vulns\":[{\"id\":\"GHSA-test\"}]}");
        ageCacheFile(48);

        final var vulns = findVulnerabilities(request(), offlineConfig());

        assertEquals(1, vulns.size());
        assertEquals("GHSA-test", vulns.get(0).id());
    }

    @Test
    public void cacheEntryWithoutVulnsMeansNoVulnerabilities() throws Exception {
        writeCache("{}");

        assertTrue(findVulnerabilities(request(), offlineConfig()).isEmpty());
    }

    @Test
    public void offlineWithoutAnyCacheFailsWithClearMessage() {
        final var exception = assertThrows(IOException.class,
                () -> findVulnerabilities(request(), offlineConfig()));

        assertTrue(exception.getMessage().contains("offline"), exception.getMessage());
        assertTrue(exception.getMessage().contains("org.yaml:snakeyaml"), exception.getMessage());
    }

    @Test
    public void corruptCacheIsTreatedAsAMiss() {
        writeCacheRaw("not json {{{");

        final var exception = assertThrows(IOException.class,
                () -> findVulnerabilities(request(), offlineConfig()));
        assertTrue(exception.getMessage().contains("offline"), exception.getMessage());
    }

    @Test
    public void truncatedCacheIsTreatedAsAMiss() {
        writeCacheRaw("{\"vulns\":[{\"id\":\"GHSA-test\"}");

        assertThrows(IOException.class, () -> findVulnerabilities(request(), offlineConfig()));
    }

    @Test
    public void emptyCacheFileIsTreatedAsAMiss() {
        writeCacheRaw("");

        assertThrows(IOException.class, () -> findVulnerabilities(request(), offlineConfig()));
    }

    @Test
    public void cacheFileNameIsTheHexDigestOfTheRequestBody() {
        writeCacheRaw("{\"vulns\":[]}");

        final var expected = encodeHex(sha256(gson.toJson(request()), UTF_8));
        assertTrue(expected.matches("[0-9a-f]{64}"), expected);
        assertTrue(Files.isRegularFile(cacheDir.resolve(expected)));
    }

    private static OsvdevRequestBody request() {
        return new OsvdevRequestBody("1.27", new PPackage("org.yaml:snakeyaml", "Maven", null));
    }

    private CacheConfig offlineConfig() {
        return new CacheConfig(true, cacheDir, ofHours(24));
    }

    private Path cacheFile() {
        return cacheDir.resolve(encodeHex(sha256(gson.toJson(request()), UTF_8)));
    }

    private void writeCache(final String content) throws IOException {
        writeCacheRaw(content);
    }

    private void writeCacheRaw(final String content) {
        try {
            Files.createDirectories(cacheDir);
            Files.writeString(cacheFile(), content);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void ageCacheFile(final int hours) throws IOException {
        Files.setLastModifiedTime(cacheFile(), FileTime.from(Instant.now().minus(Duration.ofHours(hours))));
    }

}
