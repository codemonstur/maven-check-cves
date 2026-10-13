.PHONY: help clean build test validate release-notes deploy

NAME=`xmllint --xpath "//project/artifactId/text()" pom.xml`
VERSION=`xmllint --xpath "//project/version/text()" pom.xml`
PREVIOUS_TAG=`git tag | sort -rV | head -n 1`

help:
	@echo "Available targets for $(NAME):"
	@echo "\thelp\t\t\tThis help"
	@echo "\tclean\t\t\tDelete everything in ./target"
	@echo "\tbuild\t\t\tCleans the project and rebuilds the code"
	@echo "\ttest\t\t\tRuns the tests"
	@echo "\tvalidate\t\tCheck dependency versions, cves, and licenses"
	@echo "\trelease-notes\t\tCreate release notes for the latest version"
	@echo "\tdeploy\t\t\tClean, build and deploy a version to Github and Maven Central"

clean:
	@echo "[$(NAME)] Cleaning"
	@mvn clean

build:
	@echo "[$(NAME)] Building"
	@mvn -DskipTests=true clean package

test:
	@echo "[$(NAME)] Running tests"
	@mvn test

validate:
	@mvn versions:display-dependency-updates -Dorg.slf4j.simpleLogger.defaultLogLevel=info
	@mvn versions:display-plugin-updates -Dorg.slf4j.simpleLogger.defaultLogLevel=info
	@mvn validate -P security
	@mvn validate -P licenses

release-notes:
	@echo "[$(NAME)] Writing release notes to src/docs/releases/release-$(VERSION).txt"
	@echo "$(VERSION)" > src/docs/releases/release-$(VERSION).txt
	@echo "" >> src/docs/releases/release-$(VERSION).txt
	@git log --pretty="%s" $(PREVIOUS_TAG)... master >> src/docs/releases/release-$(VERSION).txt

deploy: build
	@echo "[$(NAME)] Uploading to maven central"
	@mvn clean deploy
	@echo "[$(NAME)] Creating github release"
	@gh release create $(NAME)-$(VERSION) target/$(NAME)-$(VERSION).jar target/$(NAME)-$(VERSION)-javadoc.jar target/$(NAME)-$(VERSION)-sources.jar -F src/docs/releases/release-$(VERSION).txt
	@echo "[$(NAME)] Tagging and pushing to github"
	@git tag $(NAME)-$(VERSION)
	@git push && git push --tags
