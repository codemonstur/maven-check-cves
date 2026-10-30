package checkcves;

import bobthebuildtool.pojos.buildfile.Dependency;
import bobthebuildtool.pojos.buildfile.Project;
import bobthebuildtool.pojos.error.DependencyResolutionFailed;
import bobthebuildtool.pojos.error.VersionTooOld;
import bobthebuildtool.services.Log;
import checkcves.OsvDevRepo.CacheConfig;
import checkcves.model.internal.SeverityLevel;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.PPackage;
import checkcves.model.osvdev.Vulnerability;
import checkcves.util.DependencyResolution;
import checkcves.util.Functions;
import jcli.annotations.CliOption;
import jcli.errors.InvalidCommandLine;
import us.springett.cvss.Cvss;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static bobthebuildtool.services.Constants.YAML_PARSER;
import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static bobthebuildtool.services.Update.requireBobVersion;
import static checkcves.OsvDevRepo.findVulnerabilities;
import static java.util.Map.entry;
import static java.util.Map.ofEntries;

public enum BobPlugin {;

    public static class CliCheckCve {
        @CliOption(longName = "offline", description = "Use only the local cache")
        public boolean offline;
        @CliOption(longName = "cache-ttl-hours", defaultValue = "24", description = "Cache time-to-live in hours")
        public int cacheTtlHours = 24;
        @CliOption(longName = "cache-timeout", defaultValue = "", description = "The maximum age of a cached result. Format is a number followed by unit. ie '1m' or '5h' or '1d'")
        public String cacheTimeout = "";
        @CliOption(longName = "min-severity", defaultValue = "NONE", description = "Minimum severity that fails the build: NONE, LOW, MODERATE (or MEDIUM), HIGH, CRITICAL")
        public String minSeverity = "NONE";
        @CliOption(name = 's', longName = "suppressions", defaultValue = "src/conf/suppressions.yml", description = "The suppressions file to use (cvesearch YAML format)")
        public Path suppressions = Path.of("src/conf/suppressions.yml");
        @CliOption(name = 'f', longName = "failIfResults", description = "Fails the build if vulnerabilities were found")
        public boolean failOnFind;
        @CliOption(longName = "fields", defaultValue = "published,dependency,cve,cve_score,summary", description = "Which fields should be printed in order. Choose from [id, published, modified, dependency, cve, cve_score, summary, details]")
        public String fields = "published,dependency,cve,cve_score,summary";
    }

    public static void installPlugin(final Project project) throws VersionTooOld {
        requireBobVersion("11");
        project.addCommand("check-cve", "Checks project dependencies for known CVEs (OSV.dev)", BobPlugin::checkCVE);
    }

    /** A finding layout renders one line of output for a given dependency/vulnerability/CVE. */
    public interface FindingLayout {
        String report(Dependency dependency, Vulnerability vulnerability, String cve);
    }

    private static final Map<String, FindingLayout> FINDING_REPORT_FIELDS = ofEntries(
        entry("id", (dependency, vulnerability, cve) -> "ID         : " + vulnerability.id()),
        entry("published", (dependency, vulnerability, cve) -> "Published  : " + toHumanDate(vulnerability.published())),
        entry("modified", (dependency, vulnerability, cve) -> "Modified   : " + toHumanDate(vulnerability.modified())),
        entry("dependency", (dependency, vulnerability, cve) -> "Dependency : " + dependency.repository),
        entry("cve", (dependency, vulnerability, cve) -> "CVE        : " + (isNullOrEmpty(cve) ? "NO-CVE-LISTED" : toCVE(cve))),
        entry("cve_score", (dependency, vulnerability, cve) -> "CVSS Score : " + toCvssScore(vulnerability)),
        entry("summary", (dependency, vulnerability, cve) -> "Summary    : " + vulnerability.summary()),
        entry("details", (dependency, vulnerability, cve) -> "Details    : " + vulnerability.details())
    );

    private static final DateTimeFormatter YYYY_MM_DD_HH_MM_SS = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static int checkCVE(final Project project, final Map<String, String> environment, final String[] args)
            throws DependencyResolutionFailed, InvalidCommandLine, IOException {
        final var cli = jcli.CliParserBuilder.newCliParser(CliCheckCve::new).name("check-cve").parse(args);

        final var matcher = loadSuppressionMatcher(project, cli.suppressions);
        final var fields = cli.fields.split(",");
        final var threshold = parseMinSeverity(cli.minSeverity);

        final var ttl = parseCacheTimeout(cli.cacheTimeout, cli.cacheTtlHours);
        final var cacheConfig = new CacheConfig(cli.offline, Path.of(System.getProperty("user.home"), ".osvdev-repo"), ttl);

        int found = 0;
        for (final var lib : DependencyResolution.listProjectDependencies(project)) {
            if (isNullOrEmpty(lib.repository)) continue;
            final var gav = lib.repository.split(":");
            if (gav.length != 3) continue;

            final var request = new OsvdevRequestBody(gav[2], new PPackage(gav[0] + ":" + gav[1], "Maven", null));
            final var vulns = findVulnerabilities(request, cacheConfig);
            for (final var vuln : vulns) {
                found++;

                if (matcher.isOsvIdSuppressed(vuln.id(), lib.repository)) continue;

                final var notable = SeverityLevel.of(vuln).meets(threshold);
                if (!notable) {
                    Log.logInfo("Ignoring " + vuln.id() + " below severity threshold " + threshold + " for " + lib.repository);
                    continue;
                }

                final var aliases = vuln.aliases() == null ? List.<String>of() : vuln.aliases();
                boolean printed = false;
                for (final var cve : aliases) {
                    if (matcher.isCveSuppressed(cve, lib.repository)) continue;
                    printFinding(lib, vuln, cve, fields, cli.failOnFind);
                    printed = true;
                }
                if (aliases.isEmpty()) {
                    printFinding(lib, vuln, null, fields, cli.failOnFind);
                    printed = true;
                }
                if (!printed) {
                    // all aliases suppressed; count already incremented, nothing to print
                }
            }
        }

        if (found > 0) {
            final var message = "Found " + found + " total vulnerabilities in project dependencies";
            if (cli.failOnFind) {
                Log.logError(message);
                throw new IllegalStateException(message);
            }
            Log.logWarning(message);
        } else {
            Log.logInfo("No vulnerabilities found");
        }
        return 0;
    }

    private static void printFinding(final Dependency lib, final Vulnerability vuln, final String cve,
                                    final String[] fields, final boolean failOnFind) {
        final var logger = failOnFind ? (java.util.function.Consumer<String>) Log::logError
                                      : (java.util.function.Consumer<String>) Log::logWarning;
        final var finding = new StringBuilder();
        for (final var field : fields) {
            final var trimmed = field.trim();
            final var layout = FINDING_REPORT_FIELDS.get(trimmed);
            if (layout == null) continue;
            finding.append(layout.report(lib, vuln, cve)).append("\n");
        }
        logger.accept(finding.append(" ").toString());
    }

    // ---------- suppressions (cvesearch YAML format) ----------

    public record SuppressRule(String cve, String osvId, String gav) {}

    public static class SuppressionMatcher {
        private final Set<String> rules;

        public SuppressionMatcher(final Set<SuppressRule> set) {
            this.rules = new HashSet<>();
            for (final var rule : set) {
                if (isNullOrEmpty(rule.gav())) continue;
                if (!isNullOrEmpty(rule.cve())) rules.add(rule.gav() + "-" + rule.cve());
                if (!isNullOrEmpty(rule.osvId())) rules.add(rule.gav() + "-" + rule.osvId());
            }
        }

        public boolean isOsvIdSuppressed(final String id, final String gav) {
            return rules.contains(gav + "-" + id);
        }
        public boolean isCveSuppressed(final String cve, final String gav) {
            return rules.contains(gav + "-" + cve);
        }
    }

    private static SuppressionMatcher loadSuppressionMatcher(final Project project, final Path path) {
        try {
            final var file = project.parentDir.resolve(path);
            if (!Files.isRegularFile(file)) return new SuppressionMatcher(Set.of());
            final var loaded = YAML_PARSER.load(Files.readString(file));
            if (!(loaded instanceof Map<?, ?> map)) return new SuppressionMatcher(Set.of());
            Object rulesObj = map.get("rules");
            if (rulesObj == null) rulesObj = map.get("suppressions");
            if (!(rulesObj instanceof List<?> list)) return new SuppressionMatcher(Set.of());
            final var rules = new HashSet<SuppressRule>();
            for (final var o : list) {
                if (o instanceof Map<?, ?> m) {
                    rules.add(new SuppressRule(
                        stringOrNull(m.get("cve")),
                        stringOrNull(m.get("osvId")),
                        stringOrNull(m.get("gav"))));
                }
            }
            return new SuppressionMatcher(rules);
        } catch (final Exception e) {
            Log.logWarning("Failed to load suppressions from " + path + ": " + e);
            return new SuppressionMatcher(Set.of());
        }
    }

    private static String stringOrNull(final Object o) {
        return o == null ? null : o.toString();
    }

    // ---------- helpers ----------

    private static SeverityLevel parseMinSeverity(final String value) {
        if (value == null || value.isBlank()) return SeverityLevel.NONE;
        final var threshold = SeverityLevel.parse(value);
        if (threshold == SeverityLevel.UNKNOWN && !"UNKNOWN".equalsIgnoreCase(value.trim()))
            Log.logWarning("Unknown min-severity '" + value + "', defaulting to NONE");
        return threshold == SeverityLevel.UNKNOWN ? SeverityLevel.NONE : threshold;
    }

    private static Duration parseCacheTimeout(final String cacheTimeout, final int hours) {
        if (isNullOrEmpty(cacheTimeout)) {
            return Duration.ofHours(hours == 0 ? 24 : hours);
        }
        final var unit = switch (cacheTimeout.charAt(cacheTimeout.length() - 1)) {
            case 's', 'S' -> TimeUnit.SECONDS;
            case 'm', 'M' -> TimeUnit.MINUTES;
            case 'h', 'H' -> TimeUnit.HOURS;
            case 'd', 'D' -> TimeUnit.DAYS;
            default -> throw new IllegalArgumentException("Invalid duration value " + cacheTimeout);
        };
        final long value = Long.parseLong(cacheTimeout.substring(0, cacheTimeout.length() - 1));
        return Duration.ofMillis(unit.toMillis(value));
    }

    private static String toHumanDate(final String iso8601) {
        if (isNullOrEmpty(iso8601)) return "";
        try {
            final var instant = Instant.parse(iso8601);
            final var datetime = LocalDateTime.ofInstant(instant, ZoneId.systemDefault());
            return YYYY_MM_DD_HH_MM_SS.format(datetime);
        } catch (final Exception e) {
            return iso8601;
        }
    }

    private static String toCVE(final String cve) {
        return cve + " (https://nvd.nist.gov/vuln/detail/" + cve + ")";
    }

    private static String toCvssScore(final Vulnerability vuln) {
        if (vuln.severity() == null || vuln.severity().isEmpty()) {
            // fall back to database_specific severity if present
            if (vuln.database_specific() != null) {
                final var sev = vuln.database_specific().get("severity");
                if (sev != null) return sev.toString() + " (no vector)";
            }
            return "NO SCORE GIVEN";
        }
        final var cvss = vuln.severity().get(0).score();
        try {
            final var base = Cvss.fromVector(cvss).calculateScore().getBaseScore();
            return cvss + " (" + base + ")";
        } catch (final Exception e) {
            return cvss;
        }
    }

}
