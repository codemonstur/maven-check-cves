package checkcves;

import checkcves.model.internal.*;
import checkcves.model.osvdev.PPackage;
import checkcves.model.osvdev.Software;
import checkcves.model.osvdev.Vulnerability;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public final class ReportWriterTest {

    @TempDir
    Path tempDir;

    private static Findings findings() {
        final var findings = new Findings();
        findings.violations.add(new Violation("org.yaml", "snakeyaml", "1.27",
                List.of(vuln("GHSA-xxxx-yyyy-zzzz", "HIGH"))));
        findings.compliant.add(new Compliant("com.example", "clean-lib", "1.0"));
        findings.suppressed.add(new SuppressedFinding("org.yaml", "snakeyaml", "1.27",
                "GHSA-ssss-ssss-ssss", "waiting for upgrade", "2026-12-31"));
        findings.belowThreshold.add(new BelowThreshold("org.yaml", "snakeyaml", "1.27",
                List.of(vuln("GHSA-loww-loww-loww", "LOW"))));
        return findings;
    }

    @Test
    public void jsonReportContainsAllFindings() throws Exception {
        final var file = tempDir.resolve("reports/report.json");
        ReportWriter.writeJson(file, "com.example:app:1.0", 3, findings());

        final var root = parse(file);
        assertEquals("com.example:app:1.0", root.get("project").getAsString());
        assertEquals(3, root.get("artifactsChecked").getAsInt());

        final var violations = root.getAsJsonArray("violations");
        assertEquals(1, violations.size());
        final var violation = violations.get(0).getAsJsonObject();
        assertEquals("org.yaml", violation.get("groupId").getAsString());
        final var vulns = violation.getAsJsonArray("vulnerabilities");
        assertEquals(1, vulns.size());
        final var vuln = vulns.get(0).getAsJsonObject();
        assertEquals("GHSA-xxxx-yyyy-zzzz", vuln.get("id").getAsString());
        assertEquals("HIGH", vuln.get("severity").getAsString());
        assertEquals("https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz", vuln.get("url").getAsString());

        final var suppressed = root.getAsJsonArray("suppressed");
        assertEquals(1, suppressed.size());
        assertEquals("GHSA-ssss-ssss-ssss", suppressed.get(0).getAsJsonObject().get("vulnerabilityId").getAsString());
        assertEquals("waiting for upgrade", suppressed.get(0).getAsJsonObject().get("note").getAsString());

        final var belowThreshold = root.getAsJsonArray("belowThreshold");
        assertEquals(1, belowThreshold.size());
        assertEquals("GHSA-loww-loww-loww",
                belowThreshold.get(0).getAsJsonObject().getAsJsonArray("vulnerabilityIds").get(0).getAsString());

        assertEquals(1, root.getAsJsonArray("compliant").size());
    }

    @Test
    public void sarifReportIsWellFormed() throws Exception {
        final var file = tempDir.resolve("reports/report.sarif");
        ReportWriter.writeSarif(file, "com.example:app:1.0", "1.0.3", findings());

        final var root = parse(file);
        assertEquals("2.1.0", root.get("version").getAsString());

        final var run = root.getAsJsonArray("runs").get(0).getAsJsonObject();
        final var driver = run.getAsJsonObject("tool").getAsJsonObject("driver");
        assertEquals("maven-check-cves", driver.get("name").getAsString());

        // 1 violation + 1 below-threshold + 1 suppressed
        final var results = run.getAsJsonArray("results");
        assertEquals(3, results.size());

        final var levels = new java.util.HashMap<String, String>();
        for (final var element : results) {
            final var result = element.getAsJsonObject();
            levels.put(result.get("ruleId").getAsString(), result.get("level").getAsString());
        }
        assertEquals("error", levels.get("GHSA-xxxx-yyyy-zzzz"));
        assertEquals("note", levels.get("GHSA-loww-loww-loww"));
        assertEquals("warning", levels.get("GHSA-ssss-ssss-ssss"));

        // The suppressed result carries a SARIF suppression entry
        for (final var element : results) {
            final var result = element.getAsJsonObject();
            if (result.get("ruleId").getAsString().equals("GHSA-ssss-ssss-ssss")) {
                final var suppressions = result.getAsJsonArray("suppressions");
                assertNotNull(suppressions);
                assertEquals("waiting for upgrade",
                        suppressions.get(0).getAsJsonObject().get("justification").getAsString());
            }
        }
    }

    @Test
    public void reportFileParentDirectoriesAreCreated() throws Exception {
        final var file = tempDir.resolve("a/b/c/report.json");
        ReportWriter.writeJson(file, "com.example:app:1.0", 0, new Findings());
        assertTrue(Files.isRegularFile(file));
    }

    @Test
    public void jsonReportIncludesAliases() throws Exception {
        final var findings = new Findings();
        findings.violations.add(new Violation("com.example", "lib", "1.0",
                List.of(new Vulnerability(null, "GHSA-xxxx-yyyy-zzzz", null, null,
                        List.of("CVE-2023-34035", "CVE-2023-12345"), null, null, null, null, null, null))));

        final var file = tempDir.resolve("aliases.json");
        ReportWriter.writeJson(file, "com.example:app:1.0", 1, findings);

        final var vuln = parse(file).getAsJsonArray("violations").get(0).getAsJsonObject()
                .getAsJsonArray("vulnerabilities").get(0).getAsJsonObject();
        final var aliases = vuln.getAsJsonArray("aliases");
        assertEquals(2, aliases.size());
        assertEquals("CVE-2023-34035", aliases.get(0).getAsString());
    }

    @Test
    public void sarifLevelMappingCoversEverySeverity() throws Exception {
        final var findings = new Findings();
        findings.violations.add(new Violation("com.example", "lib", "1.0", List.of(
                vuln("GHSA-crit", "CRITICAL"), vuln("GHSA-high", "HIGH"),
                vuln("GHSA-mod", "MODERATE"), vuln("GHSA-low", "LOW"))));

        final var file = tempDir.resolve("levels.sarif");
        ReportWriter.writeSarif(file, "com.example:app:1.0", "1.0.3", findings);

        final var levels = new java.util.HashMap<String, String>();
        for (final var element : parse(file).getAsJsonArray("runs").get(0).getAsJsonObject()
                .getAsJsonArray("results")) {
            final var result = element.getAsJsonObject();
            levels.put(result.get("ruleId").getAsString(), result.get("level").getAsString());
        }
        assertEquals("error", levels.get("GHSA-crit"));
        assertEquals("error", levels.get("GHSA-high"));
        assertEquals("warning", levels.get("GHSA-mod"));
        assertEquals("warning", levels.get("GHSA-low"));
    }

    @Test
    public void emptyFindingsProduceEmptyArraysAndZeroCounts() throws Exception {
        final var file = tempDir.resolve("empty.json");
        ReportWriter.writeJson(file, "com.example:app:1.0", 0, new Findings());

        final var root = parse(file);
        assertEquals(0, root.get("artifactsChecked").getAsInt());
        assertEquals(0, root.getAsJsonArray("violations").size());
        assertEquals(0, root.getAsJsonArray("suppressed").size());
        assertEquals(0, root.getAsJsonArray("belowThreshold").size());
        assertEquals(0, root.getAsJsonArray("compliant").size());
    }

    @Test
    public void sarifWithEmptyFindingsHasEmptyResults() throws Exception {
        final var file = tempDir.resolve("empty.sarif");
        ReportWriter.writeSarif(file, "com.example:app:1.0", "1.0.3", new Findings());

        final var root = parse(file);
        assertEquals("2.1.0", root.get("version").getAsString());
        assertEquals(0, root.getAsJsonArray("runs").get(0).getAsJsonObject().getAsJsonArray("results").size());
    }

    private static JsonObject parse(final Path file) throws Exception {
        return new Gson().fromJson(Files.readString(file), JsonObject.class);
    }

    @Test
    public void jsonReportIncludesFixedInVersions() throws Exception {
        final var findings = new Findings();
        findings.violations.add(new Violation("org.yaml", "snakeyaml", "1.27",
                List.of(vulnWithFixedVersion("GHSA-fixx-fixx-fixx", "HIGH", "1.31"))));

        final var file = tempDir.resolve("fixed.json");
        ReportWriter.writeJson(file, "test:scratch:1.0", 1, findings);

        final var vuln = parse(file).getAsJsonArray("violations").get(0).getAsJsonObject()
                .getAsJsonArray("vulnerabilities").get(0).getAsJsonObject();
        assertEquals("1.31", vuln.getAsJsonArray("fixedIn").get(0).getAsString());
    }

    @Test
    public void sarifMessagesMentionTheFixVersion() throws Exception {
        final var findings = new Findings();
        findings.violations.add(new Violation("org.yaml", "snakeyaml", "1.27",
                List.of(vulnWithFixedVersion("GHSA-fixx-fixx-fixx", "HIGH", "1.31"))));

        final var file = tempDir.resolve("fixed.sarif");
        ReportWriter.writeSarif(file, "test:scratch:1.0", "1.0.3", findings);

        final var result = parse(file).getAsJsonArray("runs").get(0).getAsJsonObject()
                .getAsJsonArray("results").get(0).getAsJsonObject();
        assertTrue(result.get("message").getAsString().contains("(fixed in 1.31)"),
                result.get("message").getAsString());
    }

    private static Vulnerability vulnWithFixedVersion(final String id, final String severity, final String fixed) {
        final var range = new Software.Range("ECOSYSTEM", List.of(
                new Software.Event("0", null, null, null),
                new Software.Event(null, fixed, null, null)));
        final var affected = new Software(new PPackage("org.yaml:snakeyaml", "Maven", null), null, null, List.of(range));
        return new Vulnerability(null, id, "a summary", null, null, null, null,
                Map.of("severity", severity), null, List.of(affected), null);
    }

    private static Vulnerability vuln(final String id, final String severity) {
        return new Vulnerability(null, id, "a summary", null, null, "2023-01-01", "2022-01-01",
                Map.of("severity", severity), null, null, null);
    }

}
