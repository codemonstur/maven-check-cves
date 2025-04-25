package tools;

import checkcves.model.internal.Violation;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.PPackage;
import checkcves.model.osvdev.Vulnerability;

import java.io.IOException;
import java.util.List;

import static checkcves.OsvDevRepo.findVulnerabilities;

public class QueryOSVdev {

    public static void main(final String... args) throws IOException {
        final List<Vulnerability> vulns = findVulnerabilities(
                new OsvdevRequestBody("1.27",
                        new PPackage("org.yaml:snakeyaml", "Maven", null)));

        System.out.println(new Violation("org.yaml", "snakeyaml", "1.27", vulns).toMessage(false));
    }

}
