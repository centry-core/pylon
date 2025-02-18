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

""" RequirementsProvider """

import os
import json
import shutil

from . import RequirementsProviderModel


class Provider(RequirementsProviderModel):
    """ Provider """

    def __init__(self, context, settings):
        self.context = context
        self.settings = settings
        #
        self.path = self.settings["path"]

    def init(self):
        """ Initialize provider """
        os.makedirs(self.path, exist_ok=True)

    def deinit(self):
        """ De-initialize provider """

    def requirements_exist(self, plugin_name, cache_hash=None):
        """ Check if plugin requirements exist """
        requirements_path = os.path.join(self.path, plugin_name)
        #
        if cache_hash is None:
            return os.path.exists(requirements_path)
        #
        requirements_meta_path = os.path.join(self.path, f"{plugin_name}.json")
        #
        if os.path.exists(requirements_meta_path):
            with open(requirements_meta_path, "rb") as file:
                requirements_meta = json.load(file)
        else:
            requirements_meta = {"cache_hash": ""}
        #
        return os.path.exists(requirements_path) and requirements_meta["cache_hash"] == cache_hash

    def get_requirements(self, plugin_name, cache_hash=None, temporary_objects=None):
        """ Get plugin requirements (a.k.a user site data) """
        if not self.requirements_exist(plugin_name, cache_hash):
            return None
        #
        return os.path.join(self.path, plugin_name)

    def add_requirements(self, plugin_name, cache_hash, path):
        """ Add plugin requirements (a.k.a user site data) """
        target_path = os.path.join(self.path, plugin_name)
        #
        try:
            is_same_path = os.path.samefile(path, target_path)
        except:  # pylint: disable=W0702
            is_same_path = False
        #
        if not is_same_path:
            if os.path.exists(target_path):
                self.delete_requirements(plugin_name)
            #
            shutil.copytree(path, target_path)
        #
        with open(os.path.join(self.path, f"{plugin_name}.json"), "wb") as file:
            file.write(json.dumps({"cache_hash": cache_hash}).encode())

    def delete_requirements(self, plugin_name):
        """ Delete plugin requirements (a.k.a user site data) """
        target_path = os.path.join(self.path, plugin_name)
        #
        if os.path.exists(target_path):
            shutil.rmtree(target_path)
