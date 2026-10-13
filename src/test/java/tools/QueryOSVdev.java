package tools;

import checkcves.OsvDevRepo.CacheConfig;
import checkcves.model.internal.Violation;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.PPackage;
import checkcves.model.osvdev.Vulnerability;

import java.io.IOException;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;

import static checkcves.OsvDevRepo.findVulnerabilities;

public class QueryOSVdev {

    public static void main(final String... args) throws IOException {
        final List<Vulnerability> vulns = findVulnerabilities(
                new OsvdevRequestBody("1.27",
                        new PPackage("org.yaml:snakeyaml", "Maven", null)),
                new CacheConfig(false, Paths.get(System.getProperty("user.home")).resolve(".osvdev-repo"),
                        Duration.ofHours(24)));

        System.out.println(new Violation("org.yaml", "snakeyaml", "1.27", vulns).toMessage(false));
    }

}
