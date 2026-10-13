package checkcves.model.internal;

import checkcves.model.osvdev.Vulnerability;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;

/**
 * A structured suppression rule, configured in the pom as:
 * <pre>{@code
 * <suppressions>
 *     <suppression>
 *         <id>CVE-2023-34035</id>          <!-- vulnerability id or alias, optional -->
 *         <groupId>org.yaml</groupId>       <!-- optional GAV filter -->
 *         <artifactId>snakeyaml</artifactId><!-- optional GAV filter -->
 *         <until>2026-12-31</until>         <!-- optional expiry date (ISO-8601) -->
 *         <note>waiting for upgrade</note>  <!-- optional justification -->
 *     </suppression>
 * </suppressions>
 * }</pre>
 * All present fields must match for the rule to apply. At least one of id, groupId or artifactId
 * is required. When a suppression has an expiry date in the past it stops applying.
 */
public final class Suppression {
    public String id;
    public String groupId;
    public String artifactId;
    public String until;
    public String note;

    public boolean matches(final String gavGroupId, final String gavArtifactId, final Vulnerability vuln) {
        if (groupId != null && !groupId.equals(gavGroupId)) return false;
        if (artifactId != null && !artifactId.equals(gavArtifactId)) return false;
        if (id != null && !id.equals(vuln.id()) && !matchesAlias(vuln)) return false;
        return groupId != null || artifactId != null || id != null;
    }

    private boolean matchesAlias(final Vulnerability vuln) {
        return vuln.aliases() != null && vuln.aliases().contains(id);
    }

    /** Returns the expiry date, or null when the suppression never expires. */
    public LocalDate untilDate() {
        if (until == null || until.isBlank()) return null;
        try {
            return LocalDate.parse(until.trim());
        } catch (final DateTimeParseException e) {
            throw new IllegalArgumentException(
                    "Invalid suppression expiry date '" + until + "', expected ISO-8601 (yyyy-MM-dd)", e);
        }
    }

    public boolean isExpired() {
        final var expiry = untilDate();
        return expiry != null && expiry.isBefore(LocalDate.now());
    }
}
