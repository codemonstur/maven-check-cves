package checkcves.util;

import checkcves.model.osvdev.Vulnerability;

import java.math.BigInteger;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Pattern;

public enum Versions {;

    private static final Pattern SEPARATOR = Pattern.compile("[._\\-+]");
    private static final Pattern DIGITS = Pattern.compile("\\d+");

    /**
     * Simplified Maven version comparison: numeric segments compare numerically (so 1.9 sorts
     * before 1.10), other segments compare lexically. Not a full implementation of the Maven
     * versioning rules, but good enough to order the versions found in OSV data.
     */
    public static int compare(final String a, final String b) {
        final var left = SEPARATOR.split(a == null ? "" : a);
        final var right = SEPARATOR.split(b == null ? "" : b);
        final var common = Math.min(left.length, right.length);
        for (int i = 0; i < common; i++) {
            final var cmp = compareSegment(left[i], right[i]);
            if (cmp != 0) return cmp;
        }
        return Integer.compare(left.length, right.length);
    }

    private static int compareSegment(final String a, final String b) {
        if (DIGITS.matcher(a).matches() && DIGITS.matcher(b).matches())
            return new BigInteger(a).compareTo(new BigInteger(b));
        return a.compareTo(b);
    }

    /**
     * Returns the fix versions from the OSV affected ranges that apply to the given artifact
     * version: the ranges of the matching package where the version falls between the introduced
     * and fixed events. An empty list means no fix information is available for this version.
     */
    public static List<String> fixedVersions(final Vulnerability vuln, final String groupId,
                                             final String artifactId, final String version) {
        if (vuln.affected() == null) return List.of();

        final var packageName = groupId + ":" + artifactId;
        final var fixed = new TreeSet<String>();
        for (final var affected : vuln.affected()) {
            if (affected.ppackage() == null || !packageName.equals(affected.ppackage().name())) continue;
            if (affected.ranges() == null) continue;
            for (final var range : affected.ranges()) {
                if (range.events() == null) continue;
                String introduced = null;
                for (final var event : range.events()) {
                    if (event.introduced() != null) introduced = event.introduced();
                    if (event.fixed() != null) {
                        final var isInRange = introduced == null
                                || (compare(version, introduced) >= 0 && compare(version, event.fixed()) < 0);
                        if (isInRange) fixed.add(event.fixed());
                        introduced = null;
                    }
                }
            }
        }
        return List.copyOf(fixed);
    }

}
