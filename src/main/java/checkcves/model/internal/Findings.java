package checkcves.model.internal;

import checkcves.model.osvdev.Vulnerability;

import java.util.ArrayList;
import java.util.List;

public final class Findings {
    public final List<Violation> violations = new ArrayList<>();
    public final List<Compliant> compliant = new ArrayList<>();
    public final List<SuppressedFinding> suppressed = new ArrayList<>();
    public final List<BelowThreshold> belowThreshold = new ArrayList<>();
}
