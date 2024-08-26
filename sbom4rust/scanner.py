# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import re
import unicodedata

import toml
from lib4package.metadata import Metadata
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner


class CargoScanner:
    """
    Simple Cargo File Scanner.
    """

    DEFAULT_LICENCE = "NOASSERTION"
    DEFAULT_AUTHOR = "UNKNOWN"
    DEFAULT_PARENT = "-"
    VERSION_UNKNOWN = "NA"
    LOCK_FILE = "Cargo.lock"

    def __init__(self, debug, application=""):
        self.record = []
        self.packages = []
        self.cargo_file = None
        self.module_data = {}
        self.debug = debug
        self.application = application
        self.rust_package = SBOMPackage()
        self.rust_relationship = SBOMRelationship()
        self.rust_packages = {}
        self.rust_relationships = []
        self.license = LicenseScanner()
        self.package_metadata = Metadata("rust", debug=self.debug)

    def set_dependency_file(self, dependency_directory):
        self.dependency_file = os.path.join(dependency_directory, self.LOCK_FILE)
        self.module_valid = False
        if self.debug:
            print(f"Process {self.dependency_file}")
        if os.path.exists(self.dependency_file):
            # Load data from file
            with open(os.path.abspath(self.dependency_file), "r") as file_handle:
                self.module_data = toml.load(file_handle)

    def get_name(self):
        if self.application != "":
            return self.application
        return self.LOCK_FILE

    def show_module(self):
        print(self.module_data)

    def process_dependency(self):
        # If file not found, no metadata to process
        if len(self.module_data) > 0:
            self.metadata = {}
            self.module_valid = True
            # Find all packages
            for entry in self.module_data["package"]:
                self.packages.append([entry["name"], entry["version"]])
                # if self.application == "" or entry["name"] == self.application:
                self.add_entry(self.DEFAULT_PARENT, entry["name"], entry["version"])

            # Add dependencies afterwards so that all modules are defined
            # before dependencies resolved
            for entry in self.module_data["package"]:
                if "dependencies" in entry:
                    for dep in entry["dependencies"]:
                        dep_version = self.VERSION_UNKNOWN
                        dep_package = None
                        # Dep could specify version e.g. package version.
                        # If not get dep version from module
                        if " " in dep:
                            # Version specified
                            dep_package, dep_version = dep.split(" ")
                            # if self.get_package(dep_package, dep_version) is None:
                            #     # Need to add package
                            #     dep_version = self.add_package(dep)
                        else:
                            package = self.get_package(dep)
                            if package is None:
                                # Need to add package
                                print(f"[ERROR] Unknown package {dep} found")
                                dep_version = self.add_package(dep)
                            else:
                                dep_version = package[2]
                            dep_package = dep
                        if dep_package is not None:
                            self.add_entry(entry["name"], dep_package, dep_version)
        elif self.debug:
            print(f"[ERROR] File {self.dependency_file} not found")

    def add(self, entry):
        if entry not in self.record:
            self.record.append(entry)

    def get_package(self, name, version=None):
        for package in self.record:
            if version is None and name == package[1]:
                return package
            elif name == package[1] and version == package[2]:
                return package
        return None

    def _format_supplier(self, supplier_info, include_email=True):
        # See https://stackoverflow.com/questions/1207457/convert-a-unicode-string-to-a-string-in-python-containing-extra-symbols
        # And convert byte object to a string
        name_str = (
            unicodedata.normalize("NFKD", supplier_info)
            .encode("ascii", "ignore")
            .decode("utf-8")
        )
        if " " in name_str:
            # Get names assumed to be at least two names <first> <surname>
            names = re.findall(r"[a-zA-Z\.\]+ [A-Za-z]+ ", name_str)
        else:
            # Handle case where only single name provided
            names = [name_str]
        # Get email addresses
        if self.debug:
            print(f"{supplier_info} => {name_str} => {names}")
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,
        )
        supplier = " ".join(n for n in names)
        if include_email and len(emails) > 0:
            # Only one email can be specified, so choose last one
            supplier = supplier + "(" + emails[-1] + ")"
        return re.sub(" +", " ", supplier.strip())

    def add_entry(self, parent, name, version):
        if self.debug:
            print(f"Add entry {parent} - {name} {version}")

        self.add(
            [
                parent,
                name,
                version,
                self.DEFAULT_AUTHOR,
                self.DEFAULT_LICENCE,
            ]
        )
        self.rust_package.initialise()
        self.rust_package.set_name(name)
        self.rust_package.set_property("language", "Rust")
        self.rust_package.set_version(version)
        self.rust_package.set_evidence(self.dependency_file)
        # Enrich package data
        self.package_metadata.get_package(name)
        checksum = self.package_metadata.get_checksum(version=version)
        originator = self.package_metadata.get_originator()
        description = self.package_metadata.get_description()
        package_licence = self.package_metadata.get_license()
        homepage = self.package_metadata.get_homepage()
        download_location = self.package_metadata.get_downloadlocation()
        self.rust_package.set_filesanalysis(False)
        if originator is not None:
            if len(originator.split()) > 3:
                self.rust_package.set_supplier(
                    "Organization", self._format_supplier(originator)
                )
            elif len(originator) > 1:
                if self.debug:
                    print(f"{originator} => {self._format_supplier(originator)}")
                self.rust_package.set_supplier(
                    "Person", self._format_supplier(originator)
                )
            else:
                self.rust_package.set_supplier("UNKNOWN", "NOASSERTION")
        else:
            self.rust_package.set_supplier("UNKNOWN", "NOASSERTION")
        if package_licence is not None:
            license = self.license.find_license(package_licence)
            if self.debug:
                print(f"{package_licence} => {license}")
            # Report license as reported by metadata. If not valid SPDX, report NOASSERTION
            if license != package_licence:
                self.rust_package.set_licensedeclared("NOASSERTION")
            else:
                self.rust_package.set_licensedeclared(license)
            # Report license if valid SPDX identifier
            self.rust_package.set_licenseconcluded(license)
            # Add comment if metadata license was modified
            license_comment = ""
            if len(package_licence) > 0 and license != package_licence:
                license_comment = f"{name} declares {package_licence} which is not currently a valid SPDX License identifier or expression."
            # Report if license is deprecated
            if self.license.deprecated(license):
                deprecated_comment = f"{license} is now deprecated."
                if len(license_comment) > 0:
                    license_comment = f"{license_comment} {deprecated_comment}"
                else:
                    license_comment = deprecated_comment
            if len(license_comment) > 0:
                self.rust_package.set_licensecomments(license_comment)
        else:
            self.rust_package.set_licenseconcluded(self.DEFAULT_LICENCE)
            self.rust_package.set_licensedeclared(self.DEFAULT_LICENCE)
        if checksum is not None:
            self.rust_package.set_checksum("SHA1", checksum)
        if homepage is not None:
            self.rust_package.set_homepage(homepage)
        if download_location is not None:
            self.rust_package.set_downloadlocation(download_location)
        if description is not None:
            self.rust_package.set_summary(description)
        self.rust_package.set_purl(f"pkg:cargo/{name}@{version}")
        self.rust_packages[(name, version)] = self.rust_package.get_package()
        # Record relationship
        if parent != self.DEFAULT_PARENT:
            self.rust_relationship.initialise()
            self.rust_relationship.set_relationship(parent, "DEPENDS_ON", name)
            self.rust_relationship.set_relationship_id(
                None, self.rust_package.get_value("id")
            )
            self.rust_relationships.append(self.rust_relationship.get_relationship())
        else:
            if self.debug:
                print(f"Add relationship {parent} DESCRIBES {name}")
            self.rust_relationship.initialise()
            self.rust_relationship.set_relationship(self.application, "DESCRIBES", name)
            self.rust_relationships.append(self.rust_relationship.get_relationship())

    def get_record(self):
        return self.record

    def get_packages(self):
        return self.rust_packages

    def get_relationships(self):
        return self.rust_relationships

    def valid_module(self):
        return self.module_valid

    def show_record(self):
        for r in self.record:
            print(r)
