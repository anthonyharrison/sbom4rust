# SBOM4Rust

SBOM4Rust generates a SBOM (Software Bill of Materials) for Rust application or library in a number of formats including
[SPDX](https://www.spdx.org) and [CycloneDX](https://www.cyclonedx.org).
It identifies all the dependent components which are explicity defined in the `Cargo.lock` file and reports the relationships between the components.

It is intended to be used as part of a continuous integration system to enable accurate records of SBOMs to be maintained
and also to support subsequent audit needs to determine if a particular component (and version) has been used.

## Installation

To install use the following command:

`pip install sbom4rust`

Alternatively, just clone the repo and install dependencies using the following command:

`pip install -U -r requirements.txt`

The tool requires Python 3 (3.7+). It is recommended to use a virtual python environment especially
if you are using different versions of python. `virtualenv` is a tool for setting up virtual python environments which
allows you to have all the dependencies for the tool set up in a single environment, or have different environments set
up for testing using different versions of Python.

## Usage

```
usage: sbom4rust [-h] [-d DEPENDENCY] [--debug]
                   [--sbom {spdx,cyclonedx}] [--format {tag,json}]
                   [-o OUTPUT_FILE] [-g GRAPH] [-V]
```

```
optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit

Input:
  -d DEPENDENCY, --dependency DEPENDENCY
                        Directory containing Cargo.lock dependency file
  -a APPLICATION, --application APPLICATION
                        Name of application

Output:
  --debug               add debug information
  --sbom {spdx,cyclonedx}
                        specify type of software bill of materials (sbom) to
                        generate (default: spdx)
  --format {tag,json}   format for SPDX software bill of materials (sbom) (default: tag)
  -o OUTPUT_FILE, --output-file OUTPUT_FILE
                        output filename (default: output to stdout)
  -g GRAPH, --graph GRAPH
                        filename for dependency graph
```
					
## Operation

The `--dependency` option is used to identify the directory containing the `Cargo.lock` dependency file.
If this options is not specified, the current directory is assumed.

The `--application` option is used to specify an application within the `Cargo.lock` dependency file. If
this option is specified, only dependenciee related to the application are included. If this options is not
specified, all dependencues within the `Cargo.lock` dependency file are included.

The `--sbom` option is used to specify the format of the generated SBOM (the default is SPDX). The `--format` option
can be used to specify the formatting of the SPDX SBOM (the default is Tag Value format but JSON format is also supported).
All CycloneDX SBOMs are generated in JSON format.

The `--output-file` option is used to control the destination of the output generated by the tool. The
default is to report to the console but can be stored in a file (specified using `--output-file` option).

All module licences are reported as 'NOASSERTION'. All module suppliers are reported as 'UNKNOWN'.

The `--graph` option is used to generate a dependency graph of the components within the SBOM. The format of the graph
file is compatible with the [DOT language](https://graphviz.org/doc/info/lang.html) used by the
[GraphViz](https://graphviz.org/) application.

## Licence

Licenced under the Apache 2.0 Licence.

## Limitations

This tool is meant to support software development and security audit functions. The usefulness of the tool is dependent on the SBOM data
which is provided to the tool. Unfortunately, the tool is unable to determine the validity or completeness of such a SBOM file; users of the tool
are therefore reminded that they should assert the quality of any data which is provided to the tool.

## Feedback and Contributions

Bugs and feature requests can be made via GitHub Issues.