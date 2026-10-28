package checkcves;

import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.OsvdevResponseBody;
import checkcves.model.osvdev.Vulnerability;
import checkcves.util.DependencyResolution;
import bobthebuildtool.pojos.buildfile.Dependency;
import bobthebuildtool.pojos.buildfile.Project;
import bobthebuildtool.pojos.error.DependencyResolutionFailed;
import bobthebuildtool.pojos.error.VersionTooOld;
import bobthebuildtool.services.Log;
import jcli.annotations.CliOption;
import jcli.errors.InvalidCommandLine;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static bobthebuildtool.services.Functions.isNullOrEmpty;
import static bobthebuildtool.services.Update.requireBobVersion;
import static jcli.CliParserBuilder.newCliParser;

public enum BobPlugin {;

    public static void installPlugin(final Project project) throws VersionTooOld {
        requireBobVersion("11");
        project.addCommand("check-cve", "Checks project dependencies for known CVEs (OSV.dev)", BobPlugin::checkCVE);
    }

    public static class CliCheckCve {
        @CliOption(longName = "offline", description = "Use only the local cache")
        public boolean offline;
        @CliOption(longName = "cache-ttl-hours", defaultValue = "24", description = "Cache time-to-live in hours")
        public int cacheTtlHours = 24;
    }

    public static int checkCVE(final Project project, final Map<String, String> environment, final String[] args)
            throws DependencyResolutionFailed, InvalidCommandLine, IOException {
        final var cli = newCliParser(CliCheckCve::new).name("check-cve").parse(args);

        final var cacheConfig = new OsvDevRepo.CacheConfig(
            cli.offline,
            java.nio.file.Paths.get(System.getProperty("user.home"), ".osvdev-repo"),
            Duration.ofHours(cli.cacheTtlHours == 0 ? 24 : cli.cacheTtlHours));

        int found = 0;
        for (final var lib : DependencyResolution.listProjectDependencies(project)) {
            if (isNullOrEmpty(lib.repository)) continue;
            final var gav = lib.repository.split(":");
            if (gav.length != 3) continue;

            final var request = new OsvdevRequestBody(gav[2], new checkcves.model.osvdev.PPackage(gav[0] + ":" + gav[1], "Maven", null));
            final var vulns = OsvDevRepo.findVulnerabilities(request, cacheConfig);
            for (final var vuln : vulns) {
                found++;
                Log.logWarning("Vulnerability: " + vuln.id() + " in " + lib.repository);
                if (!isNullOrEmpty(vuln.summary())) Log.logWarning("  " + vuln.summary());
            }
        }

        if (found > 0) {
            Log.logError("Found " + found + " vulnerabilities in project dependencies");
        } else {
            Log.logInfo("No vulnerabilities found");
        }
        return found > 0 ? 1 : 0;
    }
}