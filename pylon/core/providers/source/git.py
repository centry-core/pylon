#!/usr/bin/python3
# coding=utf-8

#   Copyright 2021 getcarrier.io
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

""" SourceProvider """

import os
import json
import tempfile

from pylon.core.tools import git

from . import SourceProviderModel


class Provider(SourceProviderModel):  # pylint: disable=R0902
    """ Provider model """

    def __init__(self, context, settings):
        self.context = context
        self.settings = settings
        #
        self.branch = self.settings.get("branch", "main")
        self.depth = self.settings.get("depth", 1)
        self.delete_git_dir = self.settings.get("delete_git_dir", True)
        self.username = self.settings.get("username", None)
        self.password = self.settings.get("password", None)
        self.key_filename = self.settings.get("key_filename", None)
        self.key_data = self.settings.get("key_data", None)
        self.add_source_data = self.settings.get("add_source_data", False)
        self.add_head_data = self.settings.get("add_head_data", False)
        self.metadata_file = self.settings.get("metadata_file", "metadata.json")

    def init(self):
        """ Initialize provider """

    def deinit(self):
        """ De-initialize provider """

    def get_source(self, target):
        """ Get plugin source """
        target_path = tempfile.mkdtemp()
        self.context.module_manager.temporary_objects.append(target_path)
        #
        _, head_data = git.clone(
            target.get("source"),
            target_path,
            target.get("branch", self.branch),
            target.get("depth", self.depth),
            target.get("delete_git_dir", self.delete_git_dir),
            target.get("username", self.username),
            target.get("password", self.password),
            target.get("key_filename", self.key_filename),
            target.get("key_data", self.key_data),
            return_head_data=True,
        )
        #
        add_source_data = target.get("add_source_data", self.add_source_data)
        add_head_data = target.get("add_head_data", self.add_head_data)
        #
        if add_source_data or add_head_data:
            metadata_path = os.path.join(target_path, target.get("metadata_file", self.metadata_file))
            #
            with open(metadata_path, "rb") as file:
                metadata = json.load(file)
            #
            if add_source_data:
                metadata["git_source"] = target.get("source")
            #
            if add_head_data:
                metadata["git_head"] = head_data
            #
            with open(metadata_path, "w") as file:
                json.dump(metadata, file, indent=2)
        #
        return target_path

    def get_multiple_source(self, targets):
        """ Get plugins source """
        result = []
        #
        for target in targets:
            result.append(self.get_source(target))
        #
        return result
