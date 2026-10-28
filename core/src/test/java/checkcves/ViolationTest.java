package checkcves;

import checkcves.model.internal.Compliant;
import checkcves.model.internal.Violation;
import checkcves.model.osvdev.PPackage;
import checkcves.model.osvdev.Severity;
import checkcves.model.osvdev.Software;
import checkcves.model.osvdev.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import static checkcves.model.internal.Compliant.newCompliantComparator;
import static checkcves.model.internal.Violation.newViolationComparator;
import static checkcves.util.Functions.toSortedList;
import static org.junit.jupiter.api.Assertions.*;

public final class ViolationTest {

    @Test
    public void nonVerboseSingleVulnerabilityMessageNamesTheId() {
        final var violation = new Violation("org.yaml", "snakeyaml", "1.27", List.of(vuln("GHSA-1", null)));

        final var message = violation.toMessage(false);
        assertTrue(message.startsWith("Found vulnerability for dependency org.yaml:snakeyaml:1.27"), message);
        assertTrue(message.contains("GHSA-1"), message);
    }

    @Test
    public void nonVerboseMessageListsEveryId() {
        final var violation = new Violation("org.yaml", "snakeyaml", "1.27",
                List.of(vuln("GHSA-1", null), vuln("GHSA-2", null)));

        final var message = violation.toMessage(false);
        assertTrue(message.startsWith("Found vulnerabilities for dependency org.yaml:snakeyaml:1.27"), message);
        assertTrue(message.contains("GHSA-1"), message);
        assertTrue(message.contains("GHSA-2"), message);
    }

    @Test
    public void verboseMessageDetailsEveryVulnerability() {
        final var violation = new Violation("org.yaml", "snakeyaml", "1.27",
                List.of(vuln("GHSA-1", "HIGH"), vuln("GHSA-2", "LOW")));

        final var message = violation.toMessage(true);
        assertTrue(message.contains("https://osv.dev/vulnerability/GHSA-1"), message);
        assertTrue(message.contains("https://osv.dev/vulnerability/GHSA-2"), message);
        assertTrue(message.contains("summary of GHSA-1"), message);
        assertTrue(message.contains("summary of GHSA-2"), message);
    }

    @Test
    public void verboseMessagePrefersCvssVectorOverDatabaseSpecificSeverity() {
        final var vuln = new Vulnerability(null, "GHSA-1", null, null, null, null, null,
                Map.of("severity", "HIGH"), null, null,
                List.of(new Severity("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")));

        final var message = new Violation("org.yaml", "snakeyaml", "1.27", List.of(vuln)).toMessage(true);
        assertTrue(message.contains("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), message);
    }

    @Test
    public void verboseMessageShowsTheFixVersionWhenKnown() {
        final var range = new Software.Range("ECOSYSTEM", List.of(
                new Software.Event("0", null, null, null),
                new Software.Event(null, "1.31", null, null)));
        final var affected = new Software(new PPackage("org.yaml:snakeyaml", "Maven", null), null, null, List.of(range));
        final var vuln = new Vulnerability(null, "GHSA-1", "summary of GHSA-1", null, null, null, null,
                null, null, List.of(affected), null);

        final var message = new Violation("org.yaml", "snakeyaml", "1.27", List.of(vuln)).toMessage(true);
        assertTrue(message.contains("fixed in : 1.31"), message);
    }

    @Test
    public void verboseMessageOmitsFixLineWhenUnknown() {
        final var message = new Violation("org.yaml", "snakeyaml", "1.27",
                List.of(vuln("GHSA-1", "HIGH"))).toMessage(true);
        assertFalse(message.contains("fixed in"), message);
    }

    @Test
    public void violationComparatorSortsByGav() {
        final var violations = List.of(
                new Violation("com.b", "lib", "1.0", List.of()),
                new Violation("com.a", "lib", "2.0", List.of()),
                new Violation("com.a", "lib", "1.0", List.of()),
                new Violation("com.a", "aaa", "1.0", List.of()));

        final var sorted = toSortedList(new LinkedHashSet<>(violations), newViolationComparator());

        assertEquals(List.of("com.a:aaa:1.0", "com.a:lib:1.0", "com.a:lib:2.0", "com.b:lib:1.0"),
                sorted.stream().map(ViolationTest::toGav).toList());
    }

    @Test
    public void compliantComparatorSortsByGav() {
        final var compliant = List.of(
                new Compliant("com.b", "lib", "1.0"),
                new Compliant("com.a", "lib", "2.0"),
                new Compliant("com.a", "lib", "1.0"));

        final var sorted = toSortedList(new LinkedHashSet<>(compliant), newCompliantComparator());

        assertEquals(List.of("com.a:lib:1.0", "com.a:lib:2.0", "com.b:lib:1.0"),
                sorted.stream().map(ViolationTest::toGav).toList());
    }

    @Test
    public void compliantMessageNamesTheDependency() {
        final var message = new Compliant("com.example", "clean-lib", "1.0").toMessage();
        assertEquals("Dependency com.example:clean-lib:1.0 has no active CVEs", message);
    }

    private static String toGav(final Violation violation) {
        return violation.groupId() + ":" + violation.artifactId() + ":" + violation.version();
    }

    private static String toGav(final Compliant compliant) {
        return compliant.groupId() + ":" + compliant.artifactId() + ":" + compliant.version();
    }

    private static Vulnerability vuln(final String id, final String severity) {
        return new Vulnerability(null, id, "summary of " + id, null, null, null, null,
                severity == null ? null : Map.of("severity", severity), null, null, null);
    }

}
