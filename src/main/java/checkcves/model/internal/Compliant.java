package checkcves.model.internal;

import org.apache.maven.artifact.Artifact;

import java.util.Comparator;

public record Compliant(String groupId, String artifactId, String version) {
    public Compliant(Artifact artifact) {
        this(artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion());
    }

    public String toMessage() {
        return "Dependency " + groupId + ":" + artifactId + ":" + version + " has no active CVEs";
    }

    public static Comparator<Compliant> newCompliantComparator() {
        return Comparator.comparing(Compliant::groupId)
                .thenComparing(Compliant::artifactId)
                .thenComparing(Compliant::version);
    }

}
