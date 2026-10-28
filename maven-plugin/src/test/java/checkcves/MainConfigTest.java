package checkcves;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.plugin.MojoFailureException;
import org.junit.jupiter.api.Test;

import static checkcves.model.internal.SeverityLevel.*;
import static org.junit.jupiter.api.Assertions.*;

public final class MainConfigTest {

    @Test
    public void eachScopeFollowsItsOwnFlag() {
        final var main = new Main();
        main.includeCompileDependencies = true;
        main.includeRuntimeDependencies = false;
        main.includeProvidedDependencies = false;
        main.includeTestDependencies = false;
        main.includeSystemDependencies = false;

        assertTrue(main.selectArtifacts(artifact("compile")));
        assertFalse(main.selectArtifacts(artifact("runtime")));
        assertFalse(main.selectArtifacts(artifact("provided")));
        assertFalse(main.selectArtifacts(artifact("test")));
        assertFalse(main.selectArtifacts(artifact("system")));
    }

    @Test
    public void unknownOrNullScopeIsNeverSelected() {
        final var main = new Main();
        main.includeCompileDependencies = true;
        main.includeRuntimeDependencies = true;
        main.includeProvidedDependencies = true;
        main.includeTestDependencies = true;
        main.includeSystemDependencies = true;

        assertFalse(main.selectArtifacts(artifact(null)));
        assertFalse(main.selectArtifacts(artifact("nonsense")));
    }

    @Test
    public void scopeMatchingIsCaseInsensitive() {
        final var main = new Main();
        main.includeCompileDependencies = true;
        assertTrue(main.selectArtifacts(artifact("COMPILE")));
    }

    @Test
    public void systemScopeIgnoresTheOtherFlags() {
        final var main = new Main();
        main.includeCompileDependencies = true;
        main.includeSystemDependencies = false;
        assertFalse(main.selectArtifacts(artifact("system")));

        main.includeSystemDependencies = true;
        main.includeCompileDependencies = false;
        assertTrue(main.selectArtifacts(artifact("system")));
    }

    @Test
    public void minSeverityDefaultsToNoneWhenUnset() throws Exception {
        final var main = new Main();
        assertEquals(NONE, main.parseMinSeverity());

        main.minSeverity = "   ";
        assertEquals(NONE, main.parseMinSeverity());
    }

    @Test
    public void minSeverityParsesValidValues() throws Exception {
        final var main = new Main();

        main.minSeverity = "critical";
        assertEquals(CRITICAL, main.parseMinSeverity());

        main.minSeverity = " HIGH ";
        assertEquals(HIGH, main.parseMinSeverity());

        main.minSeverity = "MEDIUM";
        assertEquals(MODERATE, main.parseMinSeverity());
    }

    @Test
    public void minSeverityRejectsInvalidValuesWithHelpfulMessage() {
        final var main = new Main();
        main.minSeverity = "SUPERBAD";

        final var exception = assertThrows(MojoFailureException.class, main::parseMinSeverity);
        assertTrue(exception.getMessage().contains("SUPERBAD"), exception.getMessage());
        assertTrue(exception.getMessage().contains("CRITICAL"), exception.getMessage());
    }

    @Test
    public void reportFormatDefaultsToJson() throws Exception {
        final var main = new Main();
        assertEquals("json", main.parseReportFormat());

        main.reportFormat = null;
        assertEquals("json", main.parseReportFormat());
    }

    @Test
    public void reportFormatParsesJsonAndSarif() throws Exception {
        final var main = new Main();

        main.reportFormat = "sarif";
        assertEquals("sarif", main.parseReportFormat());

        main.reportFormat = " JSON ";
        assertEquals("json", main.parseReportFormat());
    }

    @Test
    public void reportFormatRejectsInvalidValues() {
        final var main = new Main();
        main.reportFormat = "xml";

        final var exception = assertThrows(MojoFailureException.class, main::parseReportFormat);
        assertTrue(exception.getMessage().contains("xml"), exception.getMessage());
    }

    private static Artifact artifact(final String scope) {
        return new DefaultArtifact("org.yaml", "snakeyaml", "1.27", scope, "jar", null,
                new DefaultArtifactHandler("jar"));
    }

}
