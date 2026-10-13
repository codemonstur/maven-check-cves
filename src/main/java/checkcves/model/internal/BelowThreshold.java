package checkcves.model.internal;

import checkcves.model.osvdev.Vulnerability;

import java.util.List;

public record BelowThreshold(String groupId, String artifactId, String version, List<Vulnerability> vulns) {}
