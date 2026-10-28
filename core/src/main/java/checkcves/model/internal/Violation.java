package checkcves.model.internal;

import checkcves.model.osvdev.Vulnerability;
import checkcves.util.Versions;

import java.util.Comparator;
import java.util.List;

public record Violation(String groupId, String artifactId, String version, List<Vulnerability> vulns) {

    public String toMessage(final boolean verbose) {
        if (!verbose) {
            if (vulns.size() == 1)
                return "Found vulnerability for dependency " + groupId + ":" + artifactId + ":" + version + ": " + vulns.get(0).id();

            final var list = vulns.stream().map(Vulnerability::id).toList();
            return "Found vulnerabilities for dependency " + groupId + ":" + artifactId + ":" + version + ": " + list;
        }

        if (vulns.size() == 1) {
            return "Found vulnerability for dependency " + groupId + ":" + artifactId + ":" + version + ":\n"
                    + toDetailedMessage(vulns.get(0));
        }
        final var builder = new StringBuilder();
        builder.append("Found vulnerabilities for dependency ")
                .append(groupId).append(":").append(artifactId).append(":").append(version).append(":\n");
        for (final var vuln : vulns) {
            builder.append(toDetailedMessage(vuln));
        }
        return builder.toString();
    }

    private String toDetailedMessage(final Vulnerability vuln) {
        final var fixed = Versions.fixedVersions(vuln, groupId, artifactId, version);
        return
            " - id       : " + vuln.id() + "\n" +
            "   url      : " + "https://osv.dev/vulnerability/" + vuln.id() + "\n" +
            "   title    : " + vuln.summary() + "\n" +
            "   severity : " + toSeverity(vuln) + "\n" +
            (fixed.isEmpty() ? "" : "   fixed in : " + String.join(", ", fixed) + "\n") +
            "   published: " + vuln.published() + "\n";
    }

    private static String toSeverity(final Vulnerability vuln) {
        if (vuln.severity() != null && !vuln.severity().isEmpty())
            return vuln.severity().get(0).score();
        if (vuln.database_specific() != null)
            return vuln.database_specific().getOrDefault("severity", "unknown").toString();
        return "unknown";
    }

    public static Comparator<Violation> newViolationComparator() {
        return Comparator.comparing(Violation::groupId)
                .thenComparing(Violation::artifactId)
                .thenComparing(Violation::version);
    }

}
