package checkcves.model.osvdev;

import com.google.gson.annotations.SerializedName;
import org.apache.maven.project.MavenProject;

public record OsvdevRequestBody(
        String version, @SerializedName("package") PPackage pPackage) {

    public OsvdevRequestBody(final MavenProject lib) {
        this(lib.getVersion(), new PPackage(lib));
    }

}

