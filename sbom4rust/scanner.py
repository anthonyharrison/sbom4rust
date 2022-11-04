# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os

import toml


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
        # If file not found, no metadata returned
        if len(self.module_data) > 0:
            self.metadata = {}
            self.module_valid = True
            # Find all packages
            for entry in self.module_data["package"]:
                self.packages.append([entry["name"], entry["version"]])
                if self.application == "" or entry["name"] == self.application:
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
                            if self.get_package(dep_package) is None:
                                # Need to add package
                                dep_version = self.add_package(dep)
                        else:
                            package = self.get_package(dep)
                            if package is None:
                                # Need to add package
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

    def get_package(self, name):
        for package in self.record:
            if name == package[1]:
                return package
        return None

    def add_entry(self, parent, name, version):
        if self.debug:
            print(f"Add entry {name} {version}")
        self.add(
            [
                parent,
                name,
                version,
                self.DEFAULT_AUTHOR,
                self.DEFAULT_LICENCE,
            ]
        )

    def add_package(self, name):
        if self.debug:
            print(f"Add package {name}")
        for package in self.packages:
            if name == package[0]:
                self.add_entry(self.DEFAULT_PARENT, name, package[1])
                return package[1]
        return None

    def get_record(self):
        return self.record

    def valid_module(self):
        return self.module_valid

    def show_record(self):
        for r in self.record:
            print(r)
