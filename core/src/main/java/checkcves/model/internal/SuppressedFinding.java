package checkcves.model.internal;

public record SuppressedFinding(String groupId, String artifactId, String version,
                                String vulnerabilityId, String note, String until) {}
