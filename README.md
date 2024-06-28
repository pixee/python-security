# security
Security toolkit for the Python community

This library includes a number of code security controls for various application security vulnerability categories. It can be used directly by programmers, but you may have been introduced to it by having it directly added to your code by automation.

Many of the APIs provided are meant to be drop-in replacements that either offer more secure defaults, harden against common attacks, or at least surface the security questions developers should answer when using risky APIs.

## Installation

To install this package from PyPI, use the following command:

`pip install security`

## Running tests

DO NOT RUN TESTS LOCALLY WITHOUT A VM/CONTAINER.

Tests will try to run "dangerous" commands (i.e. curl, netcat, etc.) and try to access sensitive files (i.e. sudoers, passwd, etc.). We do so to test the our abilities to detect and filter these types of attacks.

While all these commands are devised as innocuous, it is still not a good idea to risk exposure. They also require a specific environment to pass. We recommend using something like [act](https://github.com/nektos/act) to run the github workflow locally within a container for local development.
