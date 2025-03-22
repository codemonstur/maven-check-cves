package checkcves.model;

import org.apache.maven.artifact.Artifact;

public record Compliant(String groupId, String artifactId, String version) {
    public Compliant(Artifact artifact) {
        this(artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion());
    }

    public String toMessage() {
        return "Dependency " + groupId + ":" + artifactId + ":" + version + " has no active CVEs";
    }

}
