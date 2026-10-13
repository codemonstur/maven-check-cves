package checkcves.model.internal;

import checkcves.model.osvdev.Vulnerability;

import java.util.Locale;
import java.util.Map;

public enum SeverityLevel {
    NONE, LOW, MODERATE, HIGH, CRITICAL, UNKNOWN;

    /**
     * Lenient parse of a severity name. MEDIUM is an alias for MODERATE (NVD naming), and any
     * unrecognized or missing value maps to UNKNOWN.
     */
    public static SeverityLevel parse(final String value) {
        if (value == null) return UNKNOWN;
        return switch (value.trim().toUpperCase(Locale.ROOT)) {
            case "NONE" -> NONE;
            case "LOW" -> LOW;
            case "MODERATE", "MEDIUM" -> MODERATE;
            case "HIGH" -> HIGH;
            case "CRITICAL" -> CRITICAL;
            default -> UNKNOWN;
        };
    }

    public static SeverityLevel of(final Vulnerability vuln) {
        final Map<String, Object> databaseSpecific = vuln.database_specific();
        if (databaseSpecific == null) return UNKNOWN;
        final var severity = databaseSpecific.get("severity");
        return parse(severity == null ? null : severity.toString());
    }

    /**
     * An UNKNOWN severity counts as LOW: it passes only the lowest thresholds, so findings without
     * severity data are still reported unless the user explicitly allows LOW.
     */
    public boolean meets(final SeverityLevel threshold) {
        if (threshold == null || threshold == UNKNOWN || threshold == NONE) return true;
        final var level = this == UNKNOWN ? LOW : this;
        return level.ordinal() >= threshold.ordinal();
    }
}
