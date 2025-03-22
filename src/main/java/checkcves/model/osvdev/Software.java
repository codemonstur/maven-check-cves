package checkcves.model.osvdev;

import com.google.gson.annotations.SerializedName;

import java.util.List;
import java.util.Map;

public record Software(
        @SerializedName("package") PPackage ppackage,
        Map<String, Object> database_specific, List<String> versions) {}
