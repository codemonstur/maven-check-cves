package checkcves;

import checkcves.model.internal.Compliant;
import checkcves.model.internal.Violation;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.Vulnerability;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.IOException;
import java.util.*;

import static checkcves.OsvDevRepo.findVulnerabilities;
import static checkcves.model.internal.Compliant.newCompliantComparator;
import static checkcves.model.internal.Violation.newViolationComparator;
import static checkcves.util.Functions.*;
import static java.util.Collections.emptyList;
import static org.apache.maven.plugins.annotations.LifecyclePhase.VALIDATE;
import static org.apache.maven.plugins.annotations.ResolutionScope.COMPILE_PLUS_RUNTIME;

@Mojo( defaultPhase = VALIDATE, name = "check",
       requiresDependencyCollection = COMPILE_PLUS_RUNTIME,
       requiresDependencyResolution = COMPILE_PLUS_RUNTIME )
public final class Main extends MavenRepoMojo {

    @Parameter(defaultValue = "true")
    public boolean enabled;
    @Parameter(defaultValue = "true")
    public boolean printViolations;
    @Parameter(defaultValue = "false")
    public boolean printCompliant;
    @Parameter(defaultValue = "true")
    public boolean failBuildOnViolation;

    @Parameter(defaultValue = "true")
    public boolean checkCodeDependencies;
    @Parameter(defaultValue = "false")
    public boolean checkPluginDependencies;

    @Parameter(defaultValue = "true")
    public boolean includeCompileDependencies;
    @Parameter(defaultValue = "true")
    public boolean includeRuntimeDependencies;
    @Parameter(defaultValue = "false")
    public boolean includeProvidedDependencies;
    @Parameter(defaultValue = "false")
    public boolean includeTestDependencies;

    @Parameter(defaultValue = "true")
    public boolean verbose;

    @Parameter
    public Set<String> exclusions;

    public void execute() throws MojoFailureException {
        if (!enabled) return;

        final var log = getLog();

        try {
            boolean hasFailed = false;

            hasFailed |= checkCodeDependencies &&
                    checkArtifacts(log, loadCodeDependencies(), "code", exclusions);

            hasFailed |= checkPluginDependencies &&
                    checkArtifacts(log, loadPluginDependencies(), "plugin", exclusions);

            if (failBuildOnViolation && hasFailed) {
                throw new MojoFailureException("Violations found");
            }
        } catch (final IOException e) {
            throw new MojoFailureException(e);
        }
    }

    private boolean checkArtifacts(final Log log, final Set<Artifact> artifacts, final String type,
                                   final Set<String> exclusions) throws MojoFailureException, IOException {

        final var violations = new HashSet<Violation>();
        final var compliant = new HashSet<Compliant>();

        for (final var artifact : artifacts) {
            final var artifactProject = loadProjectFor(artifact);

            final var vulns = filterExclusions(findVulnerabilities(
                    new OsvdevRequestBody(artifactProject)), exclusions);

            if (vulns.isEmpty())
                compliant.add(new Compliant(artifact));
            else
                violations.add(new Violation(artifact, vulns));
        }

        final var pluralArtifacts = artifacts.size() != 1 ? "s" : "";
        final var pluralViolations = violations.size() != 1 ? "s" : "";
        log.info("Found " + artifacts.size() + " " + type + " artifact" + pluralArtifacts +
                " with " + violations.size() + " security violation" + pluralViolations + ".");

        if (printViolations && !violations.isEmpty()) {
            for (final var violation : toSortedList(violations, newViolationComparator())) {
                for (final var line : violation.toMessage(verbose).split("\n"))
                    log.warn(line);
            }
        }
        if (printCompliant && !compliant.isEmpty()) {
            for (final var lib : toSortedList(compliant, newCompliantComparator())) {
                for (final var line : lib.toMessage().split("\n"))
                    log.info(line);
            }
        }

        return !violations.isEmpty();
    }

    private static List<Vulnerability> filterExclusions(final List<Vulnerability> vulns, final Set<String> exclusions) {
        if (vulns == null) return emptyList();
        if (exclusions == null) return vulns;
        return vulns.stream()
            .filter(vulnerability -> !exclusions.contains(vulnerability.id()))
            .toList();
    }

    @Override
    protected boolean selectArtifacts(final Artifact artifact) {
        final var scope = artifact.getScope();
        if ("runtime".equalsIgnoreCase(scope)) return includeRuntimeDependencies;
        if ("compile".equalsIgnoreCase(scope)) return includeCompileDependencies;
        if ("provided".equalsIgnoreCase(scope)) return includeProvidedDependencies;
        if ("test".equalsIgnoreCase(scope)) return includeTestDependencies;
        return true;
    }

}