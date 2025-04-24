package checkcves;

import checkcves.model.Compliant;
import checkcves.model.Violation;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.OsvdevResponseBody;
import checkcves.model.osvdev.Vulnerability;
import com.google.gson.Gson;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugin.logging.Log;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.*;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.*;

import static checkcves.model.Compliant.newCompliantComparator;
import static checkcves.model.Violation.newViolationComparator;
import static checkcves.util.Functions.*;
import static java.net.http.HttpClient.newHttpClient;
import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toSet;
import static org.apache.maven.model.building.ModelBuildingRequest.*;
import static org.apache.maven.plugins.annotations.LifecyclePhase.VALIDATE;
import static org.apache.maven.plugins.annotations.ResolutionScope.COMPILE_PLUS_RUNTIME;

@Mojo( defaultPhase = VALIDATE, name = "check",
       requiresDependencyCollection = COMPILE_PLUS_RUNTIME,
       requiresDependencyResolution = COMPILE_PLUS_RUNTIME )
public final class MavenCheckCVEs extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    public MavenProject project;
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    public MavenSession session;
    @Component
    public ProjectBuilder projectBuilder;

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
        final var codeArtifacts = loadCodeDependencies();
        final var pluginArtifacts = loadPluginDependencies();

        try {
            boolean hasFailed = false;
            hasFailed |= checkCodeDependencies && checkArtifacts(log, codeArtifacts, exclusions);
            hasFailed |= checkPluginDependencies && checkArtifacts(log, pluginArtifacts, exclusions);

            if (failBuildOnViolation && hasFailed) {
                throw new MojoFailureException("Violations found");
            }
        } catch (final IOException e) {
            throw new MojoFailureException(e);
        }
    }

    private boolean checkArtifacts(final Log log, final Set<Artifact> artifacts, final Set<String> exclusions)
            throws MojoFailureException, IOException {

        final var http = newHttpClient();
        final var gson = new Gson();

        final var violations = new HashSet<Violation>();
        final var compliant = new HashSet<Compliant>();

        for (final var artifact : artifacts) {
            final var artifactProject = loadProjectFor(artifact);

            final var vulns = filterExclusions(findVulnerabilities(http, gson,
                    new OsvdevRequestBody(artifactProject)), exclusions);

            if (vulns.isEmpty())
                compliant.add(new Compliant(artifact));
            else
                violations.add(new Violation(artifact, vulns));
        }

        final var pluralArtifacts = artifacts.size() != 1 ? "s" : "";
        final var pluralViolations = violations.size() != 1 ? "s" : "";
        log.info("Found " + artifacts.size() + " artifact" + pluralArtifacts +
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

    private Set<Artifact> loadCodeDependencies() {
        final var set = new HashSet<Artifact>();
        set.addAll(project.getArtifacts());
        set.addAll(project.getDependencyArtifacts());
        return set.stream().filter(this::selectArtifacts).collect(toSet());
    }

    private Set<Artifact> loadPluginDependencies() {
        return project.getPluginArtifacts();
    }

    private boolean selectArtifacts(final Artifact artifact) {
        final var scope = artifact.getScope();
        if ("runtime".equalsIgnoreCase(scope)) return includeRuntimeDependencies;
        if ("compile".equalsIgnoreCase(scope)) return includeCompileDependencies;
        if ("provided".equalsIgnoreCase(scope)) return includeProvidedDependencies;
        if ("test".equalsIgnoreCase(scope)) return includeTestDependencies;
        return true;
    }

    private MavenProject loadProjectFor(final Artifact artifact) throws MojoFailureException {
        final var buildingRequest = new DefaultProjectBuildingRequest(session.getProjectBuildingRequest())
                .setValidationLevel(VALIDATION_LEVEL_MINIMAL);
        try {
            return projectBuilder.build(artifact, buildingRequest).getProject();
        } catch (final ProjectBuildingException e) {
            throw new MojoFailureException(e);
        }
    }

    // curl -v https://api.osv.dev/v1/query -d '{"version":"1.27","package":{"name":"org.yaml:snakeyaml","ecosystem":"Maven"}}'
    // curl -v https://api.osv.dev/v1/query -d '{"version":"1.15.3","package":{"name":"org.jsoup:jsoup","ecosystem":"Maven"}}'
    public static List<Vulnerability> findVulnerabilities(final HttpClient http, final Gson gson
            , final OsvdevRequestBody request) throws IOException {
        return newHttpCall(http, gson)
            .scheme("https").hostname("api.osv.dev")
            .post("/v1/query")
            .body(gson.toJson(request))
            .execute()
            .verifyNotServerError().verifySuccess()
            .fetchBodyInto(OsvdevResponseBody.class)
            .vulns();
    }

}