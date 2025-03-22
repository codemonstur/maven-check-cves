package tools;

import checkcves.model.Violation;
import checkcves.model.osvdev.OsvdevRequestBody;
import checkcves.model.osvdev.PPackage;
import checkcves.model.osvdev.Vulnerability;
import com.google.gson.Gson;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.List;

import static checkcves.MavenCheckCVEs.findVulnerabilities;

public class QueryOSVdev {

    public static void main(final String... args) throws IOException {
        final var http = HttpClient.newHttpClient();
        final var gson = new Gson();

        final List<Vulnerability> vulns = findVulnerabilities(http, gson,
                new OsvdevRequestBody("1.27",
                        new PPackage("org.yaml:snakeyaml", "Maven", null)));

        System.out.println(new Violation("org.yaml", "snakeyaml", "1.27", vulns).toMessage(false));
    }

}
