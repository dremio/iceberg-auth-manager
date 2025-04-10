<!--
Copyright (C) 2025 Dremio Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->
# Contributing to Dremio Iceberg AuthManager

Thank you for considering contributing to Dremio Iceberg AuthManager. Any contribution (code, test
cases, documentation, use cases, ...) is valuable!

This documentation will help you get started. 

## Contribute bug reports and feature requests 

You can report an issue in the [issue tracker](https://github.com/dremio/iceberg-auth-manager/issues). 

### How to report a bug

Note: If you find a  **security vulnerability**, do _NOT_  open an issue. Please email
security@dremio.com instead.

When filing an [issue](https://github.com/dremio/iceberg-auth-manager/issues), make sure to answer
these five questions:

1. What version of Dremio Iceberg AuthManager are you using?
2. What operating system and processor architecture are you using?
3. What did you do?
4. What did you expect to see?
5. What did you see instead?

### How to suggest a feature or enhancement

If you're looking for a feature that does not exist in Dremio Iceberg AuthManager, you're probably
not alone. Others likely have similar needs. Please open an
[issue](https://github.com/dremio/iceberg-auth-manager/issues) describing the feature you'd like to
see, why you need it, and how it should work.

When creating your feature request, document your requirements first. Please, try to not directly
describe the solution.

## Before you begin contributing code

### Review open issues and discuss your approach

If you want to dive into development yourself then you can check out existing open issues or
requests for features that need to be implemented. Take ownership of an issue and try fix it.

Before starting on a large code change, please describe the concept/design of what you plan to do on
the issue/feature request you intend to address. If unsure whether the design is good or will be
accepted, discuss it with the community in the respective issue first, before you do too much active
development.

### Provide your changes in a Pull Request

The best way to provide changes is to fork Dremio Iceberg AuthManager repository on GitHub and
provide a Pull Request with your changes. To make it easy to apply your changes please use the
following conventions:

* Every Pull Request should have a matching GitHub Issue.
* Create a branch that will house your change:

```bash
git clone https://github.com/dremio/iceberg-auth-manager
cd iceberg-auth-manager
git fetch --all
git checkout -b my-branch origin/main
```

Don't forget to periodically rebase your branch:

```bash
git pull --rebase
git push GitHubUser my-branch --force
```

Ensure the build passes:

```bash
./gradlew clean build
```

Ensure the code is properly formatted:

```bash
./gradlew spotlessApply
```

* Pull Requests should be based on the `main` branch.
* Test that your changes works by adapting or adding tests. Verify the build passes.
* If your Pull Request has conflicts with the `main` branch, please rebase and fix the conflicts.

## Java version requirements

The Dremio Iceberg AuthManager build currently requires Java 21 or later. There are a few tools that
help you to run the right Java version:

* [SDKMAN!](https://sdkman.io/) follow the installation instructions, then run `sdk list java` to
  see the available distributions and versions, then run `sdk install java <identifer from list>`
  using the identifier for the distribution and version (>= 21) of your choice.
* [jenv](https://www.jenv.be/) If on a Mac you can use jenv to set the appropriate SDK.

## Good Practices

* `git log` can help you find the original/relevant authors of the code you are modifying. If you
  need, feel free to tag the author in your Pull Request comment if you need assistance or review.
* Do not re-create a Pull Request for the same change.
* Consider open questions and concerns in all comments of your Pull Request, provide replies and
  resolve addressed comments, if those don't serve reference purposes. If a comment doesn't contain
  `nit`, `minor`, or `not a blocker` mention, please provide feedback to the comment before merging.
* Give time for review. For instance two working days is a good base to get first reviews and
  comments.
