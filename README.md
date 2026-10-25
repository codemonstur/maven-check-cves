
[![GitHub Release](https://img.shields.io/github/v/release/codemonstur/maven-check-cves.svg)](https://github.com/codemonstur/maven-check-cves/releases)
[![Maven Central](https://img.shields.io/maven-central/v/com.github.codemonstur/maven-check-cves.svg)](https://central.sonatype.com/artifact/com.github.codemonstur/maven-check-cves)
[![MIT Licence](https://img.shields.io/github/license/codemonstur/maven-check-cves)](LICENSE)

## Maven-check-cves

A maven plugin that checks for known vulnerabilities in the project dependencies.

By default, the plugin will fail the build if any vulnerability is found in any dependency.

The plugin will run during the `validate` phase.

### Example pom configuration

1. Add this code to the pom:
```
<plugin>
    <groupId>com.github.codemonstur</groupId>
    <artifactId>maven-check-cves</artifactId>
    <version>1.1.0</version>
    <executions>
        <execution><goals><goal>check</goal></goals></execution>
    </executions>
    <configuration>
        <enabled>true</enabled> <!-- default: true -->
        <printViolations>true</printViolations> <!-- default: true -->
        <printCompliant>false</printCompliant> <!-- default: false -->
        <failBuildOnViolation>true</failBuildOnViolation> <!-- default: true -->
        <checkCodeDependencies>true</checkCodeDependencies> <!-- default: true -->
        <checkPluginDependencies>false</checkPluginDependencies> <!-- default: false -->
        <includeCompileDependencies>true</includeCompileDependencies> <!-- default: true -->
        <includeRuntimeDependencies>true</includeRuntimeDependencies> <!-- default: true -->
        <includeProvidedDependencies>false</includeProvidedDependencies> <!-- default: false -->
        <includeTestDependencies>false</includeTestDependencies> <!-- default: false -->
        <includeSystemDependencies>false</includeSystemDependencies> <!-- default: false -->
        <verbose>true</verbose> <!-- default: true -->
        <minSeverity>HIGH</minSeverity> <!-- default: none (every finding fails the build) -->
        <exclusions> <!-- default: none -->
            <exclusion>GHSA-jfh8-c2jc-438g</exclusion>
            <exclusion>CVE-2023-34035</exclusion> <!-- aliases are matched too -->
        </exclusions>
        <suppressions> <!-- default: none -->
            <suppression>
                <groupId>org.yaml</groupId>        <!-- optional -->
                <artifactId>snakeyaml</artifactId> <!-- optional -->
                <id>CVE-2023-34035</id>            <!-- optional, matched against id and aliases -->
                <until>2026-12-31</until>          <!-- optional expiry date -->
                <note>waiting for the 2.0 upgrade</note> <!-- optional justification -->
            </suppression>
        </suppressions>
        <offline>false</offline> <!-- default: false -->
        <cacheDir>${user.home}/.osvdev-repo</cacheDir> <!-- default: ${user.home}/.osvdev-repo -->
        <cacheTtlHours>24</cacheTtlHours> <!-- default: 24 -->
        <maxConcurrentQueries>4</maxConcurrentQueries> <!-- default: 4 -->
        <reportFile>target/check-cves-report.json</reportFile> <!-- default: none (no report written) -->
        <reportFormat>json</reportFormat> <!-- default: json, alternatively sarif -->
    </configuration>
</plugin>
```
2. Run `mvn validate`

### Configuration settings

The following settings can be used for the plugin:

| config name                 | default value | description                                                                                                |
|-----------------------------|---------------|------------------------------------------------------------------------------------------------------------|
| enabled                     | true          | Turns the plugin on or off                                                                                 |
| printViolations             | true          | If true will print a warning in the log for each dependency that failed our rules                          |
| printCompliant              | false         | If true will print an info message for each dependency that passed our rules                               |
| failBuildOnViolation        | true          | If true will cause the build to fail if any dependency violates our rules                                  |
| checkCodeDependencies       | true          | If true will include all code dependencies in the pom, including transitive dependencies                   |
| checkPluginDependencies     | false         | If true will include all plugin dependencies in the pom                                                    |
| includeCompileDependencies  | true          | If true will include all dependencies with the compile scope                                               |
| includeRuntimeDependencies  | true          | If true will include all dependencies with the runtime scope                                               |
| includeProvidedDependencies | false         | If true will include all dependencies with the provided scope                                              |
| includeTestDependencies     | false         | If true will include all dependencies with the test scope                                                  |
| includeSystemDependencies   | false         | If true will include all dependencies with the system scope                                                |
| verbose                     | true          | If true will print more details about the vulnerability that was found, including the version that fixed it. If false only the ID will be shown |
| exclusions                  | none          | A list of vulnerability IDs to ignore, matched against both the vulnerability ID and its aliases           |
| minSeverity                 | none          | Minimum severity that fails the build: NONE, LOW, MODERATE (or MEDIUM), HIGH, CRITICAL. Lower findings are logged but do not fail the build. Findings without severity data count as LOW |
| suppressions                | none          | Structured suppressions with id/groupId/artifactId matching, an optional expiry date and a note. See below |
| offline                     | false         | If true only cached results are used and the OSV service is never contacted                                |
| cacheDir                    | ~/.osvdev-repo | Directory in which query results are cached                                                               |
| cacheTtlHours               | 24            | Number of hours before a cached result is refreshed. A stale entry is still used if the service is unreachable |
| maxConcurrentQueries        | 4             | Maximum number of queries to the OSV service that run in parallel                                            |
| reportFile                  | none          | If set, all findings are also written to this file (parent directories are created)                        |
| reportFormat                | json          | Format of the report file: json or sarif                                                                   |

### Severity threshold

By default every finding fails the build. With `minSeverity` set, only findings of at least that
severity count as violations; anything lower is logged as an info line and included in reports at a
lower level:

```
mvn validate -Dcheckcves.minSeverity=HIGH
```

### Suppressions

`exclusions` is the quick way to ignore a specific vulnerability everywhere. `suppressions` is the
structured alternative: every field you specify must match, so a rule can target one artifact
(`groupId` + `artifactId` without an `id` suppresses every finding for that artifact), or one
vulnerability for one artifact. The `until` date makes a suppression temporary: once it is in the
past the finding counts again, so waivers cannot be forgotten. An expired suppression is logged and
ignored.

### Reports

With `reportFile` set, the plugin writes all findings (violations, suppressions, below-threshold
findings and compliant dependencies) to a file. `sarif` output can be uploaded to GitHub code
scanning; suppressed findings are marked with a SARIF `suppressions` entry.

```
mvn validate -Dcheckcves.reportFile=target/check-cves.sarif -Dcheckcves.reportFormat=sarif
```

### Command line overrides

Every setting can also be given on the command line with the `checkcves.` prefix, for example:
`-Dcheckcves.enabled=false`, `-Dcheckcves.failBuildOnViolation=false`, `-Dcheckcves.minSeverity=CRITICAL`,
`-Dcheckcves.offline=true`. A value configured explicitly in the pom takes precedence over the
command line.
