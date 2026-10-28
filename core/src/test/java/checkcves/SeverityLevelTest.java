package checkcves;

import checkcves.model.internal.SeverityLevel;
import checkcves.model.osvdev.Vulnerability;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static checkcves.model.internal.SeverityLevel.*;
import static org.junit.jupiter.api.Assertions.*;

public final class SeverityLevelTest {

    @Test
    public void parsesKnownSeverityNames() {
        assertEquals(NONE, parse("NONE"));
        assertEquals(LOW, parse("low"));
        assertEquals(MODERATE, parse("MODERATE"));
        assertEquals(MODERATE, parse("MEDIUM"));
        assertEquals(HIGH, parse("High"));
        assertEquals(CRITICAL, parse("CRITICAL"));
    }

    @Test
    public void parsesUnknownOrMissingSeverityAsUnknown() {
        assertEquals(UNKNOWN, parse(null));
        assertEquals(UNKNOWN, parse(""));
        assertEquals(UNKNOWN, parse("BANANA"));
    }

    @Test
    public void readsSeverityFromDatabaseSpecific() {
        assertEquals(HIGH, of(vulnWithSeverity("HIGH")));
        assertEquals(UNKNOWN, of(vulnWithSeverity(null)));
    }

    @Test
    public void thresholdComparison() {
        assertTrue(CRITICAL.meets(HIGH));
        assertTrue(HIGH.meets(HIGH));
        assertFalse(LOW.meets(HIGH));
        assertTrue(MODERATE.meets(LOW));
        assertTrue(LOW.meets(NONE));
        // A threshold of UNKNOWN (unset) accepts everything
        assertTrue(LOW.meets(UNKNOWN));
        assertTrue(UNKNOWN.meets(UNKNOWN));
    }

    @Test
    public void unknownSeverityCountsAsLow() {
        assertTrue(UNKNOWN.meets(LOW));
        assertFalse(UNKNOWN.meets(MODERATE));
        assertFalse(UNKNOWN.meets(HIGH));
    }

    private static Vulnerability vulnWithSeverity(final String severity) {
        return new Vulnerability(null, "GHSA-xxxx-yyyy-zzzz", null, null, null, null, null,
                severity == null ? null : Map.of("severity", severity), null, null, null);
    }

}
