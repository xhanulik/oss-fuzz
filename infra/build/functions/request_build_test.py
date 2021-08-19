# Copyright 2020 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
"""Unit tests for Cloud Function request builds which builds projects."""
import json
import datetime
import os
import sys
import unittest
from unittest import mock

from google.cloud import ndb
from pyfakefs import fake_filesystem_unittest

sys.path.append(os.path.dirname(__file__))
# pylint: disable=wrong-import-position

import build_project
import datastore_entities
import request_build
import test_utils

# pylint: disable=no-member

PROJECTS_DIR = os.path.join(test_utils.OSS_FUZZ_DIR, 'projects')


class TestRequestBuilds(fake_filesystem_unittest.TestCase):
  """Unit tests for sync."""

  @classmethod
  def setUpClass(cls):
    cls.ds_emulator = test_utils.start_datastore_emulator()
    test_utils.wait_for_emulator_ready(cls.ds_emulator, 'datastore',
                                       test_utils.DATASTORE_READY_INDICATOR)
    test_utils.set_gcp_environment()

  def setUp(self):
    test_utils.reset_ds_emulator()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.setUpPyfakefs()

  @mock.patch('build_lib.get_signed_url', return_value='test_url')
  @mock.patch('datetime.datetime')
  def test_get_build_steps(self, mock_url, mock_time):
    """Test for get_build_steps."""
    del mock_url, mock_time
    datetime.datetime = test_utils.SpoofedDatetime
    project_yaml_contents = ('language: c++\n'
                             'sanitizers:\n'
                             '  - address\n'
                             '  - memory\n'
                             '  - undefined\n'
                             'architectures:\n'
                             '  - x86_64\n'
                             '  - i386\n')
    project = 'test-project'
    project_dir = os.path.join(PROJECTS_DIR, project)
    self.fs.create_file(os.path.join(project_dir, 'project.yaml'),
                        contents=project_yaml_contents)
    dockerfile_contents = 'test line'
    self.fs.create_file(os.path.join(project_dir, 'Dockerfile'),
                        contents=dockerfile_contents)

    image_project = 'oss-fuzz'
    base_images_project = 'oss-fuzz-base'

    expected_build_steps_file_path = test_utils.get_test_data_file_path(
        'expected_build_steps.json')

    self.fs.add_real_file(expected_build_steps_file_path)
    with open(expected_build_steps_file_path) as expected_build_steps_file:
      expected_build_steps = json.load(expected_build_steps_file)

    build_steps = build_project.get_build_steps(project, image_project,
                                                base_images_project)
    self.assertEqual(build_steps, expected_build_steps)

  def test_get_build_steps_no_project(self):
    """Test for when project isn't available in datastore."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, request_build.get_build_steps,
                        'test-project', 'oss-fuzz', 'oss-fuzz-base')

  def test_build_history(self):
    """Testing build history."""
    with ndb.Client().context():
      datastore_entities.BuildsHistory(id='test-project-fuzzing',
                    build_tag='fuzzing',
                    project='test-project',
                    build_ids=[str(i) for i in range(1, 65)]).put()
      request_build.update_build_history('test-project', '65', 'fuzzing')
      expected_build_ids = [str(i) for i in range(2, 66)]

      self.assertEqual(datastore_entities.BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_build_history_no_existing_project(self):
    """Testing build history when build history object is missing."""
    with ndb.Client().context():
      request_build.update_build_history('test-project', '1', 'fuzzing')
      expected_build_ids = ['1']

      self.assertEqual(datastore_entities.BuildsHistory.query().get().build_ids,
                       expected_build_ids)

  def test_get_project_data(self):
    """Testing get project data."""
    with ndb.Client().context():
      self.assertRaises(RuntimeError, request_build.get_project_data,
                        'test-project')

  @classmethod
  def tearDownClass(cls):
    test_utils.cleanup_emulator(cls.ds_emulator)


if __name__ == '__main__':
  unittest.main(exit=False)
