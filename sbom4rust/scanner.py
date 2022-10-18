# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import os
import toml
from operator import itemgetter


class CargoScanner:
    """
    Simple Cargo File Scanner.
    """

    DEFAULT_LICENCE = "NOASSERTION"
    DEFAULT_AUTHOR = "UNKNOWN"
    DEFAULT_PARENT = "-"
    VERSION_UNKNOWN = "NA"
    LOCK_FILE = "Cargo.lock"

    def __init__(self, debug):
        self.record = []
        self.cargo_file = None
        self.debug = debug

    def set_dependency_file(self, dependency_directory):
        self.dependency_file = os.path.join(dependency_directory, self.LOCK_FILE)
        self.module_valid = False
        if self.debug:
            print (f"Process {self.dependency_file}")
        # Load data from file
        with open(os.path.abspath(self.dependency_file), "r") as file_handle:
            self.module_data = toml.load(file_handle)

    def get_name(self):
        return self.LOCK_FILE

    def show_module(self):
        print (self.module_data)

    def process_dependency(self):
        # If file not found, no metadata returned
        if len(self.module_data) > 0:
            self.metadata = {}
            self.module_valid = True
            # Find all packages
            for entry in self.module_data['package']:
                self.add([self.DEFAULT_PARENT, entry['name'], entry['version'], self.DEFAULT_AUTHOR, self.DEFAULT_LICENCE])
            # Add dependencies afterwards so that all modules are defined before dependencies resolved
            for entry in self.module_data['package']:
                if 'dependencies' in entry:
                    for dep in entry['dependencies']:
                        #print ("\t", dep)
                        dep_version = self.VERSION_UNKNOWN
                        dep_package = None
                        # Dep could specify version e.g. package version. If not get dep version
                        if " " in dep:
                            # Version specified
                            dep_package, dep_version = dep.split(" ")
                        else:
                            package = self.get_package(dep)
                            if package is not None:
                                dep_version = package[2]
                                dep_package = dep
                        if dep_package is not None:
                            self.add([entry['name'], dep_package, dep_version, self.DEFAULT_AUTHOR,
                                  self.DEFAULT_LICENCE])
        elif self.debug:
            print (f"File {self.dependency_file} not found")

    def add(self, entry):
        if entry not in self.record:
            self.record.append(entry)

    def get_package(self, name):
        for package in self.record:
            if name == package[1]:
                return package
        return None

    def get_record(self):
        return self.record

    def valid_module(self):
        return self.module_valid

    def show_record(self):
        for r in self.record:
            print(r)
