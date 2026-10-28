package checkcves.model.osvdev;

import com.google.gson.annotations.SerializedName;

public record OsvdevRequestBody(
        String version, @SerializedName("package") PPackage pPackage) {
}

