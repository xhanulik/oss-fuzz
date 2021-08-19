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
#!/usr/bin/python2
"""Starts project build on Google Cloud Builder.

Usage: build_project.py <project_dir>
"""

from __future__ import print_function

import argparse
import datetime
import json
import logging
import os
import posixpath
import re
import sys

import six
import yaml

from oauth2client.client import GoogleCredentials
from googleapiclient.discovery import build as cloud_build

import build_lib

FUZZING_BUILD_TAG = 'fuzzing'

GCB_LOGS_BUCKET = 'oss-fuzz-gcb-logs'

DEFAULT_ARCHITECTURES = ['x86_64']
DEFAULT_ENGINES = ['libfuzzer', 'afl', 'honggfuzz']
DEFAULT_SANITIZERS = ['address', 'undefined']

LATEST_VERSION_FILENAME = 'latest.version'
LATEST_VERSION_CONTENT_TYPE = 'text/plain'

QUEUE_TTL_SECONDS = 60 * 60 * 24  # 24 hours.

PROJECTS_DIR = os.path.abspath(
    os.path.join(__file__, os.path.pardir, os.path.pardir, os.path.pardir,
                 os.path.pardir, 'projects'))


class Build:

  def __init__(self, fuzzing_engine, sanitizer, architecture):
    self.fuzzing_engine = fuzzing_engine
    self.sanitizer = sanitizer
    self.architecture = architecture

  @property
  def out(self):
    return posixpath.join(
        '/workspace/out/',
        f'{self.fuzzing_engine}-{self.sanitizer}-{self.architecture}')


class Project:

  def __init__(self, name, image_project):
    self.name = name
    self.image_project = image_project
    project_dir = os.path.join(PROJECTS_DIR, self.name)
    dockerfile_path = os.path.join(project_dir, 'Dockerfile')
    try:
      with open(dockerfile_path) as dockerfile:
        dockerfile_lines = dockerfile.readlines()
    except FileNotFoundError:
      logging.error('Project "%s" does not have a dockerfile.', self.name)
      raise
    self.workdir = workdir_from_dockerfile(dockerfile_lines)
    if not self.workdir:
      self.workdir = '/src'
    project_yaml_path = os.path.join(project_dir, 'project.yaml')
    project_yaml = load_project_yaml(project_yaml_path)
    self._sanitizers = project_yaml['sanitizers']
    self.disabled = project_yaml['disabled']
    self.architectures = project_yaml['architectures']
    self.fuzzing_engines = project_yaml['fuzzing_engines']
    self.coverage_extra_args = project_yaml['coverage_extra_args']
    self.labels = project_yaml['labels']
    self.fuzzing_language = project_yaml['language']
    self.run_tests = project_yaml['run_tests']

  @property
  def sanitizers(self):
    """Returns processed sanitizers."""
    assert isinstance(self._sanitizers, list)
    processed_sanitizers = []
    for sanitizer in self._sanitizers:
      if isinstance(sanitizer, six.string_types):
        processed_sanitizers.append(sanitizer)
      elif isinstance(sanitizer, dict):
        for key in sanitizer.keys():
          processed_sanitizers.append(key)

    return processed_sanitizers

  @property
  def image(self):
    return f'gcr.io/{self.image_project}/{self.name}'


def get_last_step_id(steps):
  return steps[-1]['id']


def set_yaml_defaults(project_yaml):
  """Sets project.yaml's default parameters."""
  project_yaml.setdefault('disabled', False)
  project_yaml.setdefault('architectures', DEFAULT_ARCHITECTURES)
  project_yaml.setdefault('sanitizers', DEFAULT_SANITIZERS)
  project_yaml.setdefault('fuzzing_engines', DEFAULT_ENGINES)
  project_yaml.setdefault('run_tests', True)
  project_yaml.setdefault('coverage_extra_args', '')
  project_yaml.setdefault('labels', {})


def is_supported_configuration(build):
  """Check if the given configuration is supported."""
  fuzzing_engine_info = build_lib.ENGINE_INFO[build.fuzzing_engine]
  if build.architecture == 'i386' and build.sanitizer != 'address':
    return False
  return (build.sanitizer in fuzzing_engine_info.supported_sanitizers and
          build.architecture in fuzzing_engine_info.supported_architectures)


def workdir_from_dockerfile(dockerfile_lines):
  """Parses WORKDIR from the Dockerfile."""
  workdir_regex = re.compile(r'\s*WORKDIR\s*([^\s]+)')
  for line in dockerfile_lines:
    match = re.match(workdir_regex, line)
    if match:
      # We need to escape '$' since they're used for subsitutions in Container
      # Builer builds.
      return match.group(1).replace('$', '$$')

  return None


def load_project_yaml(project_yaml_path):
  """Loads project yaml and sets default values."""
  with open(project_yaml_path, 'r') as project_yaml_file_handle:
    project_yaml = yaml.safe_load(project_yaml_file_handle)
  set_yaml_defaults(project_yaml)
  return project_yaml


def get_env(fuzzing_language, build):
  env_dict = {
      'FUZZING_LANGUAGE': fuzzing_language,
      'FUZZING_ENGINE': build.fuzzing_engine,
      'SANITIZER': build.sanitizer,
      'ARCHITECTURE': build.architecture,
      # Set HOME so that it doesn't point to a persisted volume (see
      # https://github.com/google/oss-fuzz/issues/6035).
      'HOME': '/root',
      'OUT': build.out,
  }
  return list(sorted([f'{key}={value}' for key, value in env_dict.items()]))


def get_compile_step(project, build, env):

  failure_msg = (
      '*' * 80 + '\nFailed to build.\nTo reproduce, run:\n'
      f'python infra/helper.py build_image {project.name}\n'
      'python infra/helper.py build_fuzzers --sanitizer '
      f'{build.sanitizer} --engine {build.fuzzing_engine} --architecture '
      f'{build.architecture} {project.name}\n' + '*' * 80)
  return {
      'name':
          project.image,
      'env':
          env,
      'args': [
          'bash',
          '-c',
          # Remove /out to make sure there are non instrumented binaries.
          # `cd /src && cd {workdir}` (where {workdir} is parsed from the
          # Dockerfile). Container Builder overrides our workdir so we need
          # to add this step to set it back.
          (f'rm -r /out && cd /src && cd {project.workdir} && '
           f'mkdir -p {build.out} && compile || '
           f'(echo "{failure_msg}" && false)'),
      ],
      # 'waitFor':
      #     build_lib.get_srcmap_step_id(),
      # 'id': get_id('compile', build),
  }


def get_id(step_type, build):
  return (f'{step_type}-{build.fuzzing_engine}-{build.sanitizer}'
          f'-{build.architecture}')


# pylint: disable=too-many-locals, too-many-statements, too-many-branches
def get_build_steps(project_name,
                    image_project,
                    base_images_project,
                    testing=False,
                    branch=None,
                    test_images=False):
  """Returns build steps for project."""

  try:
    project = Project(project_name, image_project)
    # !!! what is right way to do this?
  except FileNotFoundError:
    return []

  if project.disabled:
    logging.info('Project "%s" is disabled.', project.name)
    return []

  timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M')

  build_steps = build_lib.project_image_steps(project.name,
                                              project.image,
                                              project.fuzzing_language,
                                              branch=branch,
                                              test_images=test_images)

  # Sort engines to make AFL first to test if libFuzzer has an advantage in
  # finding bugs first since it is generally built first.
  for fuzzing_engine in sorted(project.fuzzing_engines):
    for sanitizer in project.sanitizers:
      for architecture in project.architectures:
        build = Build(fuzzing_engine, sanitizer, architecture)
        if not is_supported_configuration(build):
          continue

        env = get_env(project.fuzzing_language, build)
        compile_step = get_compile_step(project, build, env)
        build_steps.append(compile_step)

        if project.run_tests:
          failure_msg = (
              '*' * 80 + '\nBuild checks failed.\n'
              'To reproduce, run:\n'
              f'python infra/helper.py build_image {project.name}\n'
              'python infra/helper.py build_fuzzers --sanitizer '
              f'{build.sanitizer} --engine {build.fuzzing_engine} '
              f'--architecture {build.architecture} {project.name}\n'
              'python infra/helper.py check_build --sanitizer '
              f'{build.sanitizer} --engine {build.fuzzing_engine} '
              f'--architecture {build.architecture} {project.name}\n' +
              '*' * 80)

          build_steps.append(
              # Test fuzz targets.
              {
                  'name': get_runner_image_name(base_images_project, testing), # !!!
                  'env': env,
                  'args': [
                      'bash', '-c',
                      f'test_all.py || (echo "{failure_msg}" && false)'
                  ],
                  # 'waitFor': get_last_step_id(build_steps),
                  # 'id': get_id('build-check', build)
              })

        if project.labels:
          # Write target labels.
          build_steps.append({
              'name':
                  project.image,
              'env':
                  env,
              'args': [
                  '/usr/local/bin/write_labels.py',
                  json.dumps(project.labels),
                  build.out,
              ],
          })

        if build.sanitizer == 'dataflow' and build.fuzzing_engine == 'dataflow':
          dataflow_steps = dataflow_post_build_steps(project.name, env,
                                                     base_images_project,
                                                     testing)
          if dataflow_steps:
            build_steps.extend(dataflow_steps)
          else:
            sys.stderr.write('Skipping dataflow post build steps.\n')

        targets_list_filename = build_lib.get_targets_list_filename(
            build.sanitizer)
        build_steps.extend([
            # Generate targets list.
            {
                'name':
                    get_runner_image_name(base_images_project, testing),
                'env':
                    env,
                'args': [
                    'bash', '-c',
                    f'targets_list > /workspace/{targets_list_filename}'
                ],
            }
        ])
        upload_steps = get_upload_steps(project, build, timestamp,
                                        base_images_project, testing)
        build_steps.extend(upload_steps)

  return build_steps


def get_upload_steps(project, build, timestamp, base_images_project, testing):

  bucket = build_lib.get_upload_bucket(build.fuzzing_engine, testing)
  if build.architecture != 'x86_64':
    bucket += '-' + build.architecture
  stamped_name = '-'.join([project.name, build.sanitizer, timestamp])
  zip_file = stamped_name + '.zip'
  upload_url = build_lib.get_signed_url(
      build_lib.GCS_UPLOAD_URL_FORMAT.format(bucket, project.name, zip_file))
  stamped_srcmap_file = stamped_name + '.srcmap.json'
  srcmap_url = build_lib.get_signed_url(
      build_lib.GCS_UPLOAD_URL_FORMAT.format(bucket, project.name,
                                             stamped_srcmap_file))
  latest_version_file = '-'.join(
      [project.name, build.sanitizer, LATEST_VERSION_FILENAME])
  latest_version_url = build_lib.GCS_UPLOAD_URL_FORMAT.format(
      bucket, project.name, latest_version_file)
  latest_version_url = build_lib.get_signed_url(
      latest_version_url, content_type=LATEST_VERSION_CONTENT_TYPE)
  targets_list_url = build_lib.get_signed_url(
      build_lib.get_targets_list_url(bucket, project.name, build.sanitizer))
  targets_list_filename = build_lib.get_targets_list_filename(build.sanitizer)
  upload_steps = [
      # Zip binaries.
      {
          'name': project.image,
          'args': ['bash', '-c', f'cd {build.out} && zip -r {zip_file} *'],
      },
      # Upload srcmap.
      {
          'name': f'gcr.io/{base_images_project}/uploader',
          'args': [
              '/workspace/srcmap.json',
              srcmap_url,
          ],
      },
      # Upload binaries.
      {
          'name': f'gcr.io/{base_images_project}/uploader',
          'args': [
              os.path.join(build.out, zip_file),
              upload_url,
          ],
      },
      # Upload targets list.
      {
          'name': f'gcr.io/{base_images_project}/uploader',
          'args': [
              f'/workspace/{targets_list_filename}',
              targets_list_url,
          ],
      },
      # Upload the latest.version file.
      build_lib.http_upload_step(zip_file, latest_version_url,
                                 LATEST_VERSION_CONTENT_TYPE),
      # Cleanup.
      {
          'name': project.image,
          'args': [
              'bash',
              '-c',
              'rm -r ' + build.out,
          ],
      },
  ]
  return upload_steps

def get_runner_image_name(base_images_project, testing):
  image = f'gcr.io/{base_images_project}/base-runner'
  if testing:
    image += '-testing'
  return image


def dataflow_post_build_steps(project_name, env, base_images_project, testing):
  """Appends dataflow post build steps."""
  steps = build_lib.download_corpora_steps(project_name, testing)
  if not steps:
    return None

  steps.append({
      'name':
          get_runner_image_name(base_images_project, testing),
      'env':
          env + [
              'COLLECT_DFT_TIMEOUT=2h',
              'DFT_FILE_SIZE_LIMIT=65535',
              'DFT_MIN_TIMEOUT=2.0',
              'DFT_TIMEOUT_RANGE=6.0',
          ],
      'args': [
          'bash', '-c',
          ('for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*}; done && '
           'collect_dft || (echo "DFT collection failed." && false)')
      ],
      'volumes': [{
          'name': 'corpus',
          'path': '/corpus'
      }],
  })
  return steps


def get_logs_url(build_id, image_project='oss-fuzz'):
  """Returns url where logs are displayed for the build."""
  url_format = ('https://console.developers.google.com/logs/viewer?'
                'resource=build%2Fbuild_id%2F{0}&project={1}')
  return url_format.format(build_id, image_project)


# pylint: disable=no-member
def run_build(build_steps, project_name, tag):
  """Run the build for given steps on cloud build."""
  options = {}
  if 'GCB_OPTIONS' in os.environ:
    options = yaml.safe_load(os.environ['GCB_OPTIONS'])

  build_body = {
      'steps': build_steps,
      'timeout': str(build_lib.BUILD_TIMEOUT) + 's',
      'options': options,
      'logsBucket': GCB_LOGS_BUCKET,
      'tags': [project_name + '-' + tag,],
      'queueTtl': str(QUEUE_TTL_SECONDS) + 's',
  }

  credentials = GoogleCredentials.get_application_default()
  cloudbuild = cloud_build('cloudbuild',
                           'v1',
                           credentials=credentials,
                           cache_discovery=False)
  build_info = cloudbuild.projects().builds().create(projectId='oss-fuzz',
                                                     body=build_body).execute()
  build_id = build_info['metadata']['build']['id']

  print('Logs:', get_logs_url(build_id), file=sys.stderr)
  print(build_id)


def get_args(description):
  parser = argparse.ArgumentParser(sys.argv[0], description=description)
  parser.add_argument('projects', help='Projects.', nargs='+')
  parser.add_argument('--testing',
                      action='store_true',
                      required=False,
                      default=False,
                      help='Upload to testing buckets.')
  parser.add_argument('--test-images',
                      action='store_true',
                      required=False,
                      default=False,
                      help='Use testing base-images.')
  parser.add_argument('--branch',
                      required=False,
                      default=None,
                      help='Use specified OSS-Fuzz branch.')
  return parser.parse_args()


def main():
  """Build and run projects."""
  args = get_args('Builds a project on GCB.')
  logging.basicConfig(level=logging.INFO)

  image_project = 'oss-fuzz'
  base_images_project = 'oss-fuzz-base'

  for project in args.projects:
    logging.info('Getting steps for: "%s".', project)
    steps = get_build_steps(project,
                            image_project,
                            base_images_project,
                            testing=args.testing,
                            test_images=args.test_images,
                            branch=args.branch)
    if not steps:
      logging.error('No steps. Skipping build for %s.', project)
      continue

    run_build(steps, project, FUZZING_BUILD_TAG)


if __name__ == '__main__':
  main()
