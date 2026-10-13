package checkcves;

import checkcves.model.internal.Suppression;
import checkcves.model.osvdev.Vulnerability;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public final class SuppressionTest {

    private static final Vulnerability GHSA = vuln("GHSA-xxxx-yyyy-zzzz", List.of("CVE-2023-34035"));

    @Test
    public void matchesById() {
        final var suppression = suppression(s -> s.id = "GHSA-xxxx-yyyy-zzzz");
        assertTrue(suppression.matches("org.yaml", "snakeyaml", GHSA));
        assertFalse(suppression.matches("org.yaml", "snakeyaml", vuln("GHSA-other", null)));
    }

    @Test
    public void matchesByAlias() {
        final var suppression = suppression(s -> s.id = "CVE-2023-34035");
        assertTrue(suppression.matches("org.yaml", "snakeyaml", GHSA));
        assertFalse(suppression.matches("org.yaml", "snakeyaml", vuln("GHSA-other", null)));
    }

    @Test
    public void gavOnlySuppressionMatchesAllVulnerabilitiesOfArtifact() {
        final var suppression = suppression(s -> {
            s.groupId = "org.yaml";
            s.artifactId = "snakeyaml";
        });
        assertTrue(suppression.matches("org.yaml", "snakeyaml", GHSA));
        assertTrue(suppression.matches("org.yaml", "snakeyaml", vuln("GHSA-other", null)));
        assertFalse(suppression.matches("org.yaml", "otheryaml", GHSA));
        assertFalse(suppression.matches("com.example", "snakeyaml", GHSA));
    }

    @Test
    public void allPresentFieldsMustMatch() {
        final var suppression = suppression(s -> {
            s.id = "GHSA-xxxx-yyyy-zzzz";
            s.groupId = "com.example";
        });
        assertFalse(suppression.matches("org.yaml", "snakeyaml", GHSA));
    }

    @Test
    public void emptySuppressionMatchesNothing() {
        final var suppression = suppression(s -> s.note = "no criteria at all");
        assertFalse(suppression.matches("org.yaml", "snakeyaml", GHSA));
    }

    @Test
    public void futureExpiryIsNotExpired() {
        final var suppression = suppression(s -> {
            s.id = "GHSA-xxxx-yyyy-zzzz";
            s.until = LocalDate.now().plusDays(30).toString();
        });
        assertFalse(suppression.isExpired());
        assertTrue(suppression.matches("org.yaml", "snakeyaml", GHSA));
    }

    @Test
    public void pastExpiryIsExpired() {
        final var suppression = suppression(s -> {
            s.id = "GHSA-xxxx-yyyy-zzzz";
            s.until = LocalDate.now().minusDays(1).toString();
        });
        assertTrue(suppression.isExpired());
    }

    @Test
    public void noExpiryNeverExpires() {
        assertFalse(suppression(s -> s.id = "GHSA-xxxx-yyyy-zzzz").isExpired());
    }

    @Test
    public void invalidExpiryThrows() {
        final var suppression = suppression(s -> s.until = "next tuesday");
        assertThrows(IllegalArgumentException.class, suppression::isExpired);
    }

    private interface SuppressionCustomizer { void accept(Suppression suppression); }

    private static Suppression suppression(final SuppressionCustomizer customizer) {
        final var suppression = new Suppression();
        customizer.accept(suppression);
        return suppression;
    }

    private static Vulnerability vuln(final String id, final List<String> aliases) {
        return new Vulnerability(null, id, null, null, aliases, null, null, null, null, null, null);
    }

}
