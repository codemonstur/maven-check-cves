package checkcves.model.osvdev;

import com.google.gson.annotations.SerializedName;

import java.util.List;
import java.util.Map;

public record Software(
        @SerializedName("package") PPackage ppackage,
        Map<String, Object> database_specific, List<String> versions, List<Range> ranges) {

    /** An OSV affected-range: a sequence of events bounding the affected version interval. */
    public record Range(String type, List<Event> events) {}

    /** An OSV range event. Exactly one field is typically present per event. */
    public record Event(String introduced, String fixed, String last_affected, String limit) {}
}
