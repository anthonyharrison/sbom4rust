# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from sbom4python.dotgenerator import DOTGenerator
from sbom4python.generator import SBOMGenerator
from sbom4python.output import SBOMOutput
from sbom4rust.scanner import CargoScanner
from sbom4rust.version import VERSION


# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    parser = argparse.ArgumentParser(
        prog="sbom4rust",
        description=textwrap.dedent(
            """
            SBOM4Rust generates a Software Bill of Materials for the
            Rust module identifying all of the dependent components.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-d",
        "--dependency",
        action="store",
        default="",
        help="Directory containing Cargo.lock dependency file",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json"],
        help="specify format of SPDX software bill of materials (sbom) (default: tag)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    output_group.add_argument(
        "-g",
        "--graph",
        action="store",
        default="",
        help="filename for dependency graph",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "dependency": "",
        "exclude_license": False,
        "output_file": "",
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
        "graph": "",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    dependency_location = args["dependency"]

    if args["sbom"] == "spdx":
        bom_format = args["format"]
    else:
        bom_format = "json"

    if args["debug"]:
        print("SBOM type", args["sbom"])
        if args["sbom"] == "spdx":
            print("Format", bom_format)
        print("Output file", args["output_file"])
        print("Graph file", args["graph"])
        print("Directory", dependency_location)

    sbom_scan = CargoScanner(args["debug"])
    sbom_scan.set_dependency_file(dependency_location)
    sbom_scan.process_dependency()

    # If file not found, abort processing
    if not sbom_scan.valid_module():
        return -1

    # Generate SBOM file
    sbom_gen = SBOMGenerator(False, args["sbom"], args["format"])
    sbom_out = SBOMOutput(args["output_file"], bom_format)

    if args["sbom"] == "spdx":
        sbom_gen.generate_spdx(sbom_scan.get_name(), sbom_scan.get_record())
        sbom_out.generate_output(sbom_gen.get_spdx())
    else:
        sbom_gen.generate_cyclonedx(sbom_scan.get_name(), sbom_scan.get_record())
        sbom_out.generate_output(sbom_gen.get_cyclonedx())

    if len(args["graph"]) > 0:
        sbom_dot = DOTGenerator()
        sbom_dot.generatedot(sbom_gen.get_relationships())
        dot_out = SBOMOutput(args["graph"], "dot")
        dot_out.generate_output(sbom_dot.getDOT())

    return 0

if __name__ == "__main__":
    sys.exit(main())