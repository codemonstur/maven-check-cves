# maven-check-cves

A Maven plugin that checks project dependencies for known CVEs by querying the
[OSV.dev](https://osv.dev) vulnerability database.

It binds to the `validate` phase by default, so a vulnerable dependency fails the
build early — before compilation or packaging.

The original `bobplugin-cvesearch` has been retired; its features (suppressions,
configurable output fields, `--failIfResults`, cache timeout) now live in the
`check-cves-bobplugin` module of this project, which is the maintained path.

## Usage

Add the plugin to your `pom.xml`:

```xml
<build>
  <plugins>
    <plugin>
      <groupId>com.github.codemonstur</groupId>
      <artifactId>maven-check-cves</artifactId>
      <version>1.1.0</version>
      <executions>
        <execution>
          <goals>
            <goal>check</goal>
          </goals>
        </execution>
      </executions>
    </plugin>
  </plugins>
</build>
```

Every setting can also be overridden from the command line with
`-Dcheckcves.<setting>=<value>`.

## Configuration

| Setting | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Master switch for the check. |
| `printViolations` | `true` | Print each violation found. |
| `printCompliant` | `false` | Print dependencies with no known vulnerabilities. |
| `failBuildOnViolation` | `true` | Fail the build when a violation is found. |
| `scopeIncludes` | `compile,runtime,provided,test,system` | Dependency scopes to check. |
| `includePluginDependencies` | `false` | Also check the plugin's own dependencies. |
| `verbose` | `false` | Print extra diagnostic output. |
| `minSeverity` | `NONE` | Minimum severity to report: `NONE`, `LOW`, `MODERATE`, `HIGH`, `CRITICAL`. |
| `exclusions` | — | Vulnerability IDs or aliases to ignore. |
| `suppressions` | — | Structured suppressions with expiry (see below). |
| `offline` | `false` | Use only the local cache, never hit OSV.dev. |
| `cacheDir` | `~/.osvdev-repo` | Directory holding cached OSV.dev responses. |
| `cacheTtlHours` | — | How long a cached response stays valid. |
| `maxConcurrentQueries` | — | Parallelism for OSV.dev lookups. |
| `reportFile` | — | Write findings to this file. |
| `reportFormat` | — | `json` or `sarif` (SARIF uploads to GitHub code scanning). |

## Suppressions

Suppressions let you waive a finding temporarily with an expiry date, so a waiver
cannot silently rot forever:

```xml
<suppressions>
  <suppression>
    <groupId>org.example</groupId>
    <artifactId>vulnerable-lib</artifactId>
    <id>CVE-2024-1234</id>
    <until>2026-01-01</until>
    <note>Fixed in next release</note>
  </suppression>
</suppressions>
```

## How it works

1. The mojo resolves the project's dependencies (code dependencies and optionally
   plugin dependencies).
2. Each dependency's GA/version is sent to the OSV.dev API (`POST /v1/query`).
3. Responses are cached on disk, keyed per dependency, so repeat builds are fast
   and can be run offline.
4. Findings are filtered by `minSeverity` and exclusions, then reported as
   violations or compliant results.

## Building

```sh
make build
make test
```

## License

MIT
