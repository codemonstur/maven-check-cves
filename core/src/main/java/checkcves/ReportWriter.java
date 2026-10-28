package checkcves;

import checkcves.model.internal.Findings;
import checkcves.model.internal.SeverityLevel;
import checkcves.model.internal.Violation;
import checkcves.model.osvdev.Vulnerability;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static checkcves.util.Functions.toSortedCopy;
import static checkcves.util.Versions.fixedVersions;
import static java.nio.file.StandardOpenOption.*;

public enum ReportWriter {;

    private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public static void writeJson(final Path file, final String project, final int artifactsChecked,
                                 final Findings findings) throws IOException {
        final var root = new JsonObject();
        root.addProperty("format", "maven-check-cves-report");
        root.addProperty("project", project);
        root.addProperty("timestamp", Instant.now().toString());
        root.addProperty("artifactsChecked", artifactsChecked);

        final var violations = new JsonArray();
        for (final var violation : toSortedCopy(findings.violations, Violation.newViolationComparator()))
            violations.add(toJsonViolation(violation));
        root.add("violations", violations);

        final var suppressed = new JsonArray();
        for (final var finding : findings.suppressed) {
            final var entry = new JsonObject();
            entry.addProperty("groupId", finding.groupId());
            entry.addProperty("artifactId", finding.artifactId());
            entry.addProperty("version", finding.version());
            entry.addProperty("vulnerabilityId", finding.vulnerabilityId());
            entry.addProperty("note", finding.note());
            entry.addProperty("until", finding.until());
            suppressed.add(entry);
        }
        root.add("suppressed", suppressed);

        final var belowThreshold = new JsonArray();
        for (final var finding : findings.belowThreshold) {
            final var entry = new JsonObject();
            entry.addProperty("groupId", finding.groupId());
            entry.addProperty("artifactId", finding.artifactId());
            entry.addProperty("version", finding.version());
            final var ids = new JsonArray();
            finding.vulns().forEach(v -> ids.add(new JsonPrimitive(v.id())));
            entry.add("vulnerabilityIds", ids);
            belowThreshold.add(entry);
        }
        root.add("belowThreshold", belowThreshold);

        final var compliant = new JsonArray();
        for (final var lib : findings.compliant) {
            final var entry = new JsonObject();
            entry.addProperty("groupId", lib.groupId());
            entry.addProperty("artifactId", lib.artifactId());
            entry.addProperty("version", lib.version());
            compliant.add(entry);
        }
        root.add("compliant", compliant);

        write(file, gson.toJson(root));
    }

    public static void writeSarif(final Path file, final String project, final String pluginVersion,
                                  final Findings findings) throws IOException {
        final var results = new JsonArray();
        for (final var violation : findings.violations)
            for (final var vuln : violation.vulns())
                results.add(sarifResult(vuln, violation.groupId(), violation.artifactId(),
                        violation.version(), sarifLevel(SeverityLevel.of(vuln))));
        for (final var finding : findings.belowThreshold)
            for (final var vuln : finding.vulns())
                results.add(sarifResult(vuln, finding.groupId(), finding.artifactId(),
                        finding.version(), "note"));
        for (final var finding : findings.suppressed) {
            final var result = sarifResult(finding.vulnerabilityId(),
                    finding.groupId() + ":" + finding.artifactId() + ":" + finding.version(),
                    finding.groupId(), finding.artifactId(), finding.version(), "warning");
            final var suppression = new JsonObject();
            suppression.addProperty("kind", "external");
            suppression.addProperty("justification",
                    finding.note() != null ? finding.note() : "Suppressed by maven-check-cves configuration");
            final var suppressions = new JsonArray();
            suppressions.add(suppression);
            result.add("suppressions", suppressions);
            results.add(result);
        }

        final var driver = new JsonObject();
        driver.addProperty("name", "maven-check-cves");
        driver.addProperty("informationUri", "https://github.com/codemonstur/maven-check-cves");
        driver.addProperty("version", pluginVersion);

        final var tool = new JsonObject();
        tool.add("driver", driver);

        final var run = new JsonObject();
        run.add("tool", tool);
        run.addProperty("project", project);
        run.add("results", results);

        final var root = new JsonObject();
        root.addProperty("$schema", "https://json.schemastore.org/sarif-2.1.0.json");
        root.addProperty("version", "2.1.0");
        final var runs = new JsonArray();
        runs.add(run);
        root.add("runs", runs);

        write(file, gson.toJson(root));
    }

    private static JsonObject toJsonViolation(final Violation violation) {
        final var entry = new JsonObject();
        entry.addProperty("groupId", violation.groupId());
        entry.addProperty("artifactId", violation.artifactId());
        entry.addProperty("version", violation.version());
        final var vulns = new JsonArray();
        for (final var vuln : violation.vulns())
            vulns.add(toJsonVulnerability(vuln, violation.groupId(), violation.artifactId(), violation.version()));
        entry.add("vulnerabilities", vulns);
        return entry;
    }

    private static JsonObject toJsonVulnerability(final Vulnerability vuln, final String groupId,
                                                  final String artifactId, final String version) {
        final var entry = new JsonObject();
        entry.addProperty("id", vuln.id());
        entry.addProperty("url", "https://osv.dev/vulnerability/" + vuln.id());
        entry.addProperty("summary", vuln.summary());
        entry.addProperty("severity", SeverityLevel.of(vuln).name());
        entry.addProperty("published", vuln.published());
        if (vuln.aliases() != null) {
            final var aliases = new JsonArray();
            vuln.aliases().forEach(alias -> aliases.add(new JsonPrimitive(alias)));
            entry.add("aliases", aliases);
        }
        final var fixed = fixedVersions(vuln, groupId, artifactId, version);
        if (!fixed.isEmpty()) {
            final var fixedIn = new JsonArray();
            fixed.forEach(fixedVersion -> fixedIn.add(new JsonPrimitive(fixedVersion)));
            entry.add("fixedIn", fixedIn);
        }
        return entry;
    }

    private static JsonObject sarifResult(final Vulnerability vuln, final String groupId, final String artifactId,
                                          final String version, final String level) {
        final var fixed = fixedVersions(vuln, groupId, artifactId, version);
        return sarifResult(vuln.id(),
                "Vulnerability " + vuln.id() + " in " + groupId + ":" + artifactId + ":" + version
                + (vuln.summary() != null ? ": " + vuln.summary() : "")
                + (fixed.isEmpty() ? "" : " (fixed in " + String.join(", ", fixed) + ")"),
                groupId, artifactId, version, level);
    }

    private static JsonObject sarifResult(final String ruleId, final String message, final String groupId,
                                          final String artifactId, final String version, final String level) {
        final var result = new JsonObject();
        result.addProperty("ruleId", ruleId);
        result.addProperty("level", level);
        result.addProperty("message", message);
        final var properties = new JsonObject();
        properties.addProperty("groupId", groupId);
        properties.addProperty("artifactId", artifactId);
        properties.addProperty("version", version);
        result.add("properties", properties);
        return result;
    }

    private static String sarifLevel(final SeverityLevel severity) {
        return switch (severity) {
            case CRITICAL, HIGH -> "error";
            default -> "warning";
        };
    }

    private static void write(final Path file, final String content) throws IOException {
        final var parent = file.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        Files.writeString(file, content, CREATE, TRUNCATE_EXISTING);
    }

}
