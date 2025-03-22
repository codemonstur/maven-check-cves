
[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.codemonstur/maven-check-cves/badge.svg)](http://mvnrepository.com/artifact/com.github.codemonstur/maven-check-cves)
[![MIT Licence](https://badges.frapsoft.com/os/mit/mit.svg?v=103)](https://opensource.org/licenses/mit-license.php)

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
    <version>1.0.0</version>
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
        <verbose>true</verbose> <!-- default: true -->
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
| includeCompileDependencies  | true          | If true will include all dependencies with the compile scope                                               |                            |
| includeRuntimeDependencies  | true          | If true will include all dependencies with the runtime scope                                               | 
| includeProvidedDependencies | false         | If true will include all dependencies with the provided scope                                              |
| includeTestDependencies     | false         | If true will include all dependencies with the test scope                                                  |
| verbose                     | true          | If true will print more details about the vulnerability that was found. If false only the ID will be shown |
