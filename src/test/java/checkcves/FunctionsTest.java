package checkcves;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static checkcves.util.Functions.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

public final class FunctionsTest {

    @TempDir
    Path tempDir;

    @Test
    public void sha256MatchesKnownTestVector() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                encodeHex(sha256("abc", UTF_8)));
    }

    @Test
    public void isNewerThanComparesFileAgeAgainstDuration() throws Exception {
        final var file = Files.writeString(tempDir.resolve("f"), "x");
        assertTrue(isNewerThan(file, Duration.ofHours(1)));

        age(file, 48);
        assertFalse(isNewerThan(file, Duration.ofHours(24)));
        assertTrue(isNewerThan(file, Duration.ofHours(72)));
    }

    @Test
    public void isNewerThanAlsoSupportsTimeUnits() throws Exception {
        final var file = Files.writeString(tempDir.resolve("f"), "x");
        assertTrue(isNewerThan(file, TimeUnit.DAYS, 1));

        age(file, 48);
        assertFalse(isNewerThan(file, TimeUnit.DAYS, 1));
    }

    @Test
    public void toSortedListOrdersByTheGivenComparator() {
        final var input = new LinkedHashSet<>(List.of("banana", "apple", "cherry"));

        assertEquals(List.of("apple", "banana", "cherry"), toSortedList(input, (a, b) -> a.compareTo(b)));
        assertEquals(List.of("cherry", "banana", "apple"), toSortedList(input, (a, b) -> b.compareTo(a)));
    }

    @Test
    public void encodeHexIsReversibleWithHexFormat() {
        final var data = new byte[] {0x00, 0x0f, (byte) 0xff, 0x10};
        assertEquals("000fff10", encodeHex(data));
    }

    private static void age(final Path file, final int hours) throws Exception {
        Files.setLastModifiedTime(file, FileTime.from(Instant.now().minus(Duration.ofHours(hours))));
    }

}
