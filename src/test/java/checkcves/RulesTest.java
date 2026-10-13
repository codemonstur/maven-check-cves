package checkcves;

import checkcves.model.internal.Violation;
import checkcves.model.osvdev.Vulnerability;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static checkcves.Main.filterExclusions;
import static checkcves.util.Functions.encodeHex;
import static checkcves.util.Functions.sha256;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

public final class RulesTest {

    @Test
    public void encodeHexProducesOnlyHexCharacters() {
        for (int i = 0; i < 1000; i++) {
            final var encoded = encodeHex(sha256("payload-" + i, UTF_8));
            assertTrue(encoded.matches("[0-9a-f]+"), "not valid hex: " + encoded);
        }
    }

    @Test
    public void hexEncodedCachePathIsAlwaysWritable() throws Exception {
        final var dir = Files.createTempDirectory("checkcves-test");
        for (int i = 0; i < 1000; i++) {
            final var cacheFile = dir.resolve(encodeHex(sha256("payload-" + i, UTF_8)));
            Files.writeString(cacheFile, "data");
            assertTrue(Files.isRegularFile(cacheFile));
        }
    }

    @Test
    public void exclusionsMatchIdAndAliases() {
        final var vuln = new Vulnerability(null, "GHSA-xxxx-yyyy-zzzz", null, null,
                List.of("CVE-2023-34035"), null, null, null, null, null, null);

        assertEquals(List.of(), filterExclusions(List.of(vuln), Set.of("GHSA-xxxx-yyyy-zzzz")));
        assertEquals(List.of(), filterExclusions(List.of(vuln), Set.of("CVE-2023-34035")));
        assertEquals(List.of(vuln), filterExclusions(List.of(vuln), Set.of("CVE-9999-99999")));
    }

    @Test
    public void exclusionsHandleNullInputs() {
        assertEquals(List.of(), filterExclusions(null, Set.of("GHSA-xxxx-yyyy-zzzz")));

        final var vuln = new Vulnerability(null, "GHSA-xxxx-yyyy-zzzz", null, null,
                null, null, null, null, null, null, null);
        assertEquals(List.of(vuln), filterExclusions(List.of(vuln), null));
    }

    @Test
    public void violationMessageHandlesMissingSeverity() {
        final var vuln = new Vulnerability(null, "GHSA-xxxx-yyyy-zzzz", "a summary", null,
                null, null, null, null, null, null, null);
        final var violation = new Violation("org.yaml", "snakeyaml", "1.27", List.of(vuln));

        final var message = violation.toMessage(true);
        assertTrue(message.contains("GHSA-xxxx-yyyy-zzzz"));
        assertTrue(message.contains("severity : unknown"));
    }

    @Test
    public void violationMessageHandlesSeverityFromDatabaseSpecific() {
        final var vuln = new Vulnerability(null, "GHSA-xxxx-yyyy-zzzz", "a summary", null,
                null, null, null, Map.of("severity", "HIGH"), null, null, null);
        final var violation = new Violation("org.yaml", "snakeyaml", "1.27", List.of(vuln));

        assertTrue(violation.toMessage(true).contains("severity : HIGH"));
    }

}
