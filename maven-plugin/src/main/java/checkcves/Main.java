package checkcves;

import checkcves.OsvDevRepo.CacheConfig;
import checkcves.model.internal.BelowThreshold;
import checkcves.model.internal.Compliant;
import checkcves.model.internal.Findings;
import checkcves.model.internal.SeverityLevel;
import checkcves.model.internal.SuppressedFinding;
import checkcves.model.internal.Suppression;
import checkcves.model.internal.Violation;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.Vulnerability;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Pattern;

import static checkcves.OsvDevRepo.findVulnerabilities;
import static checkcves.model.internal.Compliant.newCompliantComparator;
import static checkcves.model.internal.Violation.newViolationComparator;
import static checkcves.util.Functions.daemonThreadFactory;
import static checkcves.util.Functions.toSortedCopy;
import static java.time.Duration.ofHours;
import static java.util.Collections.emptyList;
import static java.util.Locale.ROOT;
import static org.apache.maven.plugins.annotations.LifecyclePhase.VALIDATE;
import static org.apache.maven.plugins.annotations.ResolutionScope.COMPILE_PLUS_RUNTIME;

@Mojo( defaultPhase = VALIDATE, name = "check", threadSafe = true,
       requiresDependencyCollection = COMPILE_PLUS_RUNTIME,
       requiresDependencyResolution = COMPILE_PLUS_RUNTIME )
public final class Main extends MavenRepoMojo {

    @Parameter(defaultValue = "true", property = "checkcves.enabled")
    public boolean enabled;
    @Parameter(defaultValue = "true", property = "checkcves.printViolations")
    public boolean printViolations;
    @Parameter(defaultValue = "false", property = "checkcves.printCompliant")
    public boolean printCompliant;
    @Parameter(defaultValue = "true", property = "checkcves.failBuildOnViolation")
    public boolean failBuildOnViolation;

    @Parameter(defaultValue = "true", property = "checkcves.checkCodeDependencies")
    public boolean checkCodeDependencies;
    @Parameter(defaultValue = "false", property = "checkcves.checkPluginDependencies")
    public boolean checkPluginDependencies;

    @Parameter(defaultValue = "true", property = "checkcves.includeCompileDependencies")
    public boolean includeCompileDependencies;
    @Parameter(defaultValue = "true", property = "checkcves.includeRuntimeDependencies")
    public boolean includeRuntimeDependencies;
    @Parameter(defaultValue = "false", property = "checkcves.includeProvidedDependencies")
    public boolean includeProvidedDependencies;
    @Parameter(defaultValue = "false", property = "checkcves.includeTestDependencies")
    public boolean includeTestDependencies;
    @Parameter(defaultValue = "false", property = "checkcves.includeSystemDependencies")
    public boolean includeSystemDependencies;

    @Parameter(defaultValue = "true", property = "checkcves.verbose")
    public boolean verbose;

    /** Vulnerability ids (or aliases, e.g. CVE ids) to always ignore. */
    @Parameter
    public Set<String> exclusions;

    /** Structured suppressions with GAV matching, expiry dates and notes. See the README. */
    @Parameter
    public List<Suppression> suppressions;

    /** Minimum severity that fails the build: NONE, LOW, MODERATE (or MEDIUM), HIGH, CRITICAL. */
    @Parameter(property = "checkcves.minSeverity")
    public String minSeverity;

    /** Maximum number of parallel queries to the OSV service. */
    @Parameter(defaultValue = "4", property = "checkcves.maxConcurrentQueries")
    public int maxConcurrentQueries;

    /** When true, only cached results are used and the OSV service is never contacted. */
    @Parameter(defaultValue = "false", property = "checkcves.offline")
    public boolean offline;
    @Parameter(defaultValue = "${user.home}/.osvdev-repo", property = "checkcves.cacheDir")
    public String cacheDir;
    @Parameter(defaultValue = "24", property = "checkcves.cacheTtlHours")
    public int cacheTtlHours;

    /** When set, writes all findings to this file in the format given by reportFormat. */
    @Parameter(property = "checkcves.reportFile")
    public String reportFile;
    /** Format of the report file: json or sarif. */
    @Parameter(defaultValue = "json", property = "checkcves.reportFormat")
    public String reportFormat;

    public void execute() throws MojoFailureException {
        if (!enabled) return;

        // In a multi-module build, run the check only once, on the last module, aggregating every module there.
        if (session != null && session.getProjects() != null && session.getProjects().size() > 1) {
            final var lastProject = session.getProjects().get(session.getProjects().size() - 1);
            if (lastProject == null || !project.getArtifactId().equals(lastProject.getArtifactId())) {
                getLog().debug("Skipping CVE check on non-aggregating module " + project.getArtifactId());
                return;
            }
        }

        final var log = getLog();

        try {
            validateSuppressions();
            final var threshold = parseMinSeverity();
            final var reportFormat = parseReportFormat();
            final var cacheConfig = new CacheConfig(offline, Paths.get(cacheDir), ofHours(cacheTtlHours));
            final var findings = new Findings();
            var artifactsChecked = 0;

            if (checkCodeDependencies) {
                final var artifacts = loadCodeDependencies();
                artifactsChecked += artifacts.size();
                checkArtifacts(log, artifacts, "code", threshold, cacheConfig, findings);
            }
            if (checkPluginDependencies) {
                final var artifacts = loadPluginDependencies();
                artifactsChecked += artifacts.size();
                checkArtifacts(log, artifacts, "plugin", threshold, cacheConfig, findings);
            }

            if (reportFile != null)
                writeReport(log, reportFormat, artifactsChecked, findings);

            if (failBuildOnViolation && !findings.violations.isEmpty()) {
                throw new MojoFailureException("Violations found");
            }
        } catch (final IOException e) {
            throw new MojoFailureException(e);
        }
    }

    private void checkArtifacts(final Log log, final Set<Artifact> artifacts, final String type,
                                final SeverityLevel threshold, final CacheConfig cacheConfig,
                                final Findings findings) throws MojoFailureException, IOException {

        // Phase 1: build the query bodies (local, sequential)
        final var queries = new ArrayList<Query>();
        for (final var artifact : artifacts)
            queries.add(new Query(artifact, new OsvdevRequestBody(loadProjectFor(artifact))));

        // Phase 2: query the OSV service (network, parallel with bounded concurrency)
        final var results = queryVulnerabilities(queries, cacheConfig);

        // Phase 3: filter and classify (local, sequential for deterministic log output)
        final var violations = new ArrayList<Violation>();
        final var compliant = new ArrayList<Compliant>();
        final var expiredLogged = new HashSet<String>();

        for (int i = 0; i < queries.size(); i++) {
            final var artifact = queries.get(i).artifact();
            final var vulns = filterExclusions(results.get(i), exclusions);

            final var notSuppressed = new ArrayList<Vulnerability>();
            for (final var vuln : vulns) {
                final var suppression = findSuppression(artifact, vuln, log, expiredLogged);
                if (suppression == null) {
                    notSuppressed.add(vuln);
                } else {
                    findings.suppressed.add(new SuppressedFinding(artifact.getGroupId(), artifact.getArtifactId(),
                            artifact.getVersion(), vuln.id(), suppression.note, suppression.until));
                    log.info("Suppressed " + vuln.id() + " for " + toGav(artifact) + describe(suppression));
                }
            }

            final var notable = new ArrayList<Vulnerability>();
            final var minor = new ArrayList<Vulnerability>();
            for (final var vuln : notSuppressed)
                (SeverityLevel.of(vuln).meets(threshold) ? notable : minor).add(vuln);

            if (!minor.isEmpty()) {
                findings.belowThreshold.add(new BelowThreshold(artifact.getGroupId(), artifact.getArtifactId(),
                        artifact.getVersion(), minor));
                log.info("Ignoring " + minor.size() + " finding(s) below " + threshold + " for " + toGav(artifact)
                        + ": " + minor.stream().map(Vulnerability::id).toList());
            }

            if (notable.isEmpty())
                compliant.add(new Compliant(artifact));
            else
                violations.add(new Violation(artifact, notable));
        }

        final var pluralArtifacts = artifacts.size() != 1 ? "s" : "";
        final var pluralViolations = violations.size() != 1 ? "s" : "";
        log.info("Found " + artifacts.size() + " " + type + " artifact" + pluralArtifacts +
                " with " + violations.size() + " security violation" + pluralViolations + ".");

        if (printViolations && !violations.isEmpty()) {
            for (final var violation : toSortedCopy(violations, newViolationComparator())) {
                for (final var line : violation.toMessage(verbose).split("\n"))
                    log.warn(line);
            }
        }
        if (printCompliant && !compliant.isEmpty()) {
            for (final var lib : toSortedCopy(compliant, newCompliantComparator())) {
                for (final var line : lib.toMessage().split("\n"))
                    log.info(line);
            }
        }

        findings.violations.addAll(violations);
        findings.compliant.addAll(compliant);
    }

    /**
     * Queries the OSV service for every artifact in parallel, bounded by maxConcurrentQueries.
     * Results are returned in submission order. Any failure is reported with the artifact it
     * belongs to, so a timeout or offline miss names the dependency that caused it.
     */
    private List<List<Vulnerability>> queryVulnerabilities(final List<Query> queries, final CacheConfig cacheConfig)
            throws IOException {
        if (queries.isEmpty()) return List.of();

        final var executor = Executors.newFixedThreadPool(
                Math.max(1, Math.min(maxConcurrentQueries, queries.size())),
                daemonThreadFactory("checkcves-query-"));
        try {
            final var futures = new ArrayList<Future<List<Vulnerability>>>();
            for (final var query : queries)
                futures.add(executor.submit(() -> findVulnerabilities(query.body(), cacheConfig)));

            final var results = new ArrayList<List<Vulnerability>>();
            for (int i = 0; i < futures.size(); i++) {
                try {
                    results.add(futures.get(i).get());
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while checking " + toGav(queries.get(i).artifact()), e);
                } catch (final ExecutionException e) {
                    final var cause = e.getCause() == null ? e : e.getCause();
                    if (cause instanceof IOException ioException)
                        throw new IOException("Failed checking " + toGav(queries.get(i).artifact())
                                + ": " + ioException.getMessage(), ioException);
                    throw new IOException("Failed checking " + toGav(queries.get(i).artifact()), cause);
                }
            }
            return results;
        } finally {
            executor.shutdownNow();
        }
    }

    private record Query(Artifact artifact, OsvdevRequestBody body) {}

    private Suppression findSuppression(final Artifact artifact, final Vulnerability vuln, final Log log,
                                        final Set<String> expiredLogged) {
        if (suppressions == null) return null;
        for (final var suppression : suppressions) {
            if (!suppression.matches(artifact.getGroupId(), artifact.getArtifactId(), vuln)) continue;
            if (suppression.isExpired()) {
                final var key = describeCriteria(suppression) + "|" + artifact.getGroupId() + ":" + artifact.getArtifactId();
                if (expiredLogged.add(key))
                    log.info("Ignoring expired suppression " + describeCriteria(suppression) + " (until "
                            + suppression.until + ") for " + artifact.getGroupId() + ":" + artifact.getArtifactId());
                continue;
            }
            return suppression;
        }
        return null;
    }

    /** Fails the build with a clear message on malformed suppressions, before any checking starts. */
    private void validateSuppressions() throws MojoFailureException {
        if (suppressions == null) return;
        for (final var suppression : suppressions) {
            if (suppression.id == null && suppression.groupId == null && suppression.artifactId == null)
                throw new MojoFailureException("Invalid suppression: at least one of id, groupId or artifactId"
                        + " is required (note and until alone match nothing)");
            try {
                suppression.untilDate();
            } catch (final IllegalArgumentException e) {
                throw new MojoFailureException(e.getMessage());
            }
        }
    }

    SeverityLevel parseMinSeverity() throws MojoFailureException {
        if (minSeverity == null || minSeverity.isBlank()) return SeverityLevel.NONE;
        final var threshold = SeverityLevel.parse(minSeverity);
        if (threshold == SeverityLevel.UNKNOWN)
            throw new MojoFailureException("Invalid minSeverity '" + minSeverity
                    + "'. Valid values are: NONE, LOW, MODERATE (or MEDIUM), HIGH, CRITICAL");
        return threshold;
    }

    String parseReportFormat() throws MojoFailureException {
        if (reportFormat == null || reportFormat.isBlank()) return "json";
        final var format = reportFormat.trim().toLowerCase(ROOT);
        if (!format.equals("json") && !format.equals("sarif"))
            throw new MojoFailureException("Invalid reportFormat '" + reportFormat
                    + "'. Valid values are: json, sarif");
        return format;
    }

    private void writeReport(final Log log, final String reportFormat, final int artifactsChecked,
                             final Findings findings) throws MojoFailureException, IOException {
        final var projectCoordinates =
                project.getGroupId() + ":" + project.getArtifactId() + ":" + project.getVersion();
        if (reportFormat.equals("json")) {
            ReportWriter.writeJson(Paths.get(reportFile), projectCoordinates, artifactsChecked, findings);
        } else {
            ReportWriter.writeSarif(Paths.get(reportFile), projectCoordinates, pluginVersion(), findings);
        }
        log.info("Wrote " + reportFormat.toUpperCase(ROOT) + " report to " + reportFile);
    }

    /** The version of this plugin, read from the embedded plugin descriptor. */
    private static String pluginVersion() {
        final var implementationVersion = Main.class.getPackage().getImplementationVersion();
        if (implementationVersion != null) return implementationVersion;
        try (final var descriptor = Main.class.getResourceAsStream("/META-INF/maven/plugin.xml")) {
            if (descriptor != null) {
                final var xml = new String(descriptor.readAllBytes(), StandardCharsets.UTF_8);
                final var matcher = Pattern.compile("<version>([^<]+)</version>").matcher(xml);
                if (matcher.find()) return matcher.group(1);
            }
        } catch (final IOException ignored) {
        }
        return "dev";
    }

    private static String toGav(final Artifact artifact) {
        return artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion();
    }

    private static String describeCriteria(final Suppression suppression) {
        if (suppression.id != null) return "id '" + suppression.id + "'";
        return "gav '" + suppression.groupId + ":" + suppression.artifactId + "'";
    }

    private static String describe(final Suppression suppression) {
        final var builder = new StringBuilder();
        if (suppression.until != null && !suppression.until.isBlank())
            builder.append(" until ").append(suppression.until);
        if (suppression.note != null && !suppression.note.isBlank())
            builder.append(" (").append(suppression.note).append(")");
        return builder.toString();
    }

    static List<Vulnerability> filterExclusions(final List<Vulnerability> vulns, final Set<String> exclusions) {
        if (vulns == null) return emptyList();
        if (exclusions == null) return vulns;
        return vulns.stream()
            .filter(vulnerability -> !isExcluded(vulnerability, exclusions))
            .toList();
    }

    private static boolean isExcluded(final Vulnerability vulnerability, final Set<String> exclusions) {
        if (exclusions.contains(vulnerability.id())) return true;
        return vulnerability.aliases() != null
                && vulnerability.aliases().stream().anyMatch(exclusions::contains);
    }

    @Override
    protected boolean selectArtifacts(final Artifact artifact) {
        final var scope = artifact.getScope();
        if ("runtime".equalsIgnoreCase(scope)) return includeRuntimeDependencies;
        if ("compile".equalsIgnoreCase(scope)) return includeCompileDependencies;
        if ("provided".equalsIgnoreCase(scope)) return includeProvidedDependencies;
        if ("test".equalsIgnoreCase(scope)) return includeTestDependencies;
        if ("system".equalsIgnoreCase(scope)) return includeSystemDependencies;
        return false;
    }

}
