package checkcves.model.osvdev;

import org.apache.maven.project.MavenProject;

public record PPackage(String name, String ecosystem, String purl) {
    public PPackage(final MavenProject lib) {
        this(lib.getGroupId() + ":" + lib.getArtifactId(), "Maven", null);
    }
}
