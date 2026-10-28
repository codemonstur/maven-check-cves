package checkcves;

import bobthebuildtool.pojos.buildfile.Project;

import java.nio.file.Path;

public final class CliMain {;

    public static void main(final String[] args) throws Exception {
        final Project project = new Project(Path.of(".").toAbsolutePath(), Path.of("bobfile"));
        final int exitCode = checkcves.Cli.run(project, System.getenv(), args);
        if (exitCode != 0) System.exit(exitCode);
    }
}