package checkcves;

import checkcves.model.osvdev.PPackage;
import checkcves.model.osvdev.Software;
import checkcves.model.osvdev.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;

import static checkcves.util.Versions.compare;
import static checkcves.util.Versions.fixedVersions;
import static org.junit.jupiter.api.Assertions.*;

public final class VersionsTest {

    @Test
    public void numericSegmentsCompareNumerically() {
        assertTrue(compare("1.9", "1.10") < 0);
        assertTrue(compare("1.27", "1.31") < 0);
        assertTrue(compare("2.0", "1.33") > 0);
        assertEquals(0, compare("1.2.3", "1.2.3"));
    }

    @Test
    public void longerVersionWithEqualPrefixIsGreater() {
        assertTrue(compare("1.2", "1.2.1") < 0);
        assertTrue(compare("1.2.1", "1.2") > 0);
    }

    @Test
    public void nonNumericSegmentsCompareLexically() {
        assertTrue(compare("1.0-alpha", "1.0-beta") < 0);
    }

    @Test
    public void comparisonIsNullSafe() {
        assertTrue(compare(null, "1.0") < 0);
        assertEquals(0, compare(null, null));
    }

    @Test
    public void fixedVersionsReturnsTheFixForAnAffectedVersion() {
        final var vuln = vulnWithRange("org.yaml:snakeyaml", "0", "1.31");
        assertEquals(List.of("1.31"), fixedVersions(vuln, "org.yaml", "snakeyaml", "1.27"));
    }

    @Test
    public void fixedVersionsIsEmptyWhenVersionIsAtOrAboveTheFix() {
        final var vuln = vulnWithRange("org.yaml:snakeyaml", "0", "1.31");
        assertTrue(fixedVersions(vuln, "org.yaml", "snakeyaml", "1.31").isEmpty());
        assertTrue(fixedVersions(vuln, "org.yaml", "snakeyaml", "1.32").isEmpty());
    }

    @Test
    public void fixedVersionsRespectsTheIntroducedBound() {
        final var vuln = vulnWithRange("org.yaml:snakeyaml", "1.10", "1.31");
        assertEquals(List.of("1.31"), fixedVersions(vuln, "org.yaml", "snakeyaml", "1.27"));
        assertTrue(fixedVersions(vuln, "org.yaml", "snakeyaml", "1.9").isEmpty());
    }

    @Test
    public void fixedVersionsOnlyMatchesTheSamePackage() {
        final var vuln = vulnWithRange("org.yaml:snakeyaml", "0", "1.31");
        assertTrue(fixedVersions(vuln, "com.example", "other", "1.27").isEmpty());
    }

    @Test
    public void fixedVersionsIsNullSafe() {
        final var vuln = new Vulnerability(null, "GHSA-test", null, null, null, null, null,
                null, null, null, null);
        assertTrue(fixedVersions(vuln, "org.yaml", "snakeyaml", "1.27").isEmpty());
    }

    private static Vulnerability vulnWithRange(final String packageName, final String introduced, final String fixed) {
        final var range = new Software.Range("ECOSYSTEM", List.of(
                new Software.Event(introduced, null, null, null),
                new Software.Event(null, fixed, null, null)));
        final var affected = new Software(new PPackage(packageName, "Maven", null), null, null, List.of(range));
        return new Vulnerability(null, "GHSA-test", null, null, null, null, null, null, null,
                List.of(affected), null);
    }

}
