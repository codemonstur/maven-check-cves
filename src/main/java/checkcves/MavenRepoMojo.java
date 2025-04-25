package checkcves;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.DefaultProjectBuildingRequest;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuilder;
import org.apache.maven.project.ProjectBuildingException;

import java.util.HashSet;
import java.util.Set;

import static java.util.stream.Collectors.toSet;
import static org.apache.maven.model.building.ModelBuildingRequest.VALIDATION_LEVEL_MINIMAL;

public abstract class MavenRepoMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    public MavenProject project;
    @Parameter(defaultValue = "${session}", readonly = true, required = true)
    public MavenSession session;
    @Component
    public ProjectBuilder projectBuilder;

    protected Set<Artifact> loadCodeDependencies() {
        final var set = new HashSet<Artifact>();
        set.addAll(project.getArtifacts());
        set.addAll(project.getDependencyArtifacts());
        return set.stream().filter(this::selectArtifacts).collect(toSet());
    }

    protected Set<Artifact> loadPluginDependencies() {
        return project.getPluginArtifacts();
    }

    protected abstract boolean selectArtifacts(final Artifact artifact);

    protected MavenProject loadProjectFor(final Artifact artifact) throws MojoFailureException {
        final var buildingRequest = new DefaultProjectBuildingRequest(session.getProjectBuildingRequest())
                .setValidationLevel(VALIDATION_LEVEL_MINIMAL);
        try {
            return projectBuilder.build(artifact, buildingRequest).getProject();
        } catch (final ProjectBuildingException e) {
            throw new MojoFailureException(e);
        }
    }

}
