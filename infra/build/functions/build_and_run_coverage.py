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
"""Starts and runs coverage build on Google Cloud Builder.
Usage: build_and_run_coverage.py project
"""
import datetime
import json
import logging
import os

import build_lib
import build_project

SANITIZER = 'coverage'
FUZZING_ENGINE = 'libfuzzer'
ARCHITECTURE = 'x86_64'

PLATFORM = 'linux'

COVERAGE_BUILD_TAG = 'coverage'

# Where code coverage reports need to be uploaded to.
COVERAGE_BUCKET_NAME = 'oss-fuzz-coverage'

# This is needed for ClusterFuzz to pick up the most recent reports data.

LATEST_REPORT_INFO_CONTENT_TYPE = 'application/json'

# Languages from project.yaml that have code coverage support.
LANGUAGES_WITH_COVERAGE_SUPPORT = ['c', 'c++', 'go', 'jvm', 'rust']


class URLInfo:

  def __init__(self, project, date, platform, testing):
    self.coverage_bucket_name = 'oss-fuzz-coverage'
    if testing:
      self.coverage_bucket_name += '-testing'

    self.date = date
    self.project = project
    self.html_report_url = (
        f'{build_lib.GCS_URL_BASENAME}{self.coverage_bucket_name}/{project}'
        f'/reports/{date}/{platform}/index.html')
    self.latest_report_info_url = (f'/{COVERAGE_BUCKET_NAME}'
                                   f'/latest_report_info/{project}.json')

  def get_upload_url(self, upload_type):
    return (f'gs://{self.coverage_bucket_name}/{self.project}'
            f'/{upload_type}/{self.date}')


# pylint: disable=too-many-locals
def get_build_steps(project_name,
                    image_info,
                    testing=False,
                    branch=None,
                    test_images=False):
  """Returns build steps for project."""
  project_yaml, dockerfile_lines = build_project.get_project_data(project_name)
  if project_yaml['disabled']:
    logging.info('Project "%s" is disabled.', project_name)
    return []

  if project_yaml['language'] not in LANGUAGES_WITH_COVERAGE_SUPPORT:
    logging.info(
        'Project "%s" is written in "%s", coverage is not supported yet.',
        project_name, project_yaml['language'])
    return []

  image = build_project.get_project_image(image_info, project_name)
  report_date = datetime.datetime.now().strftime('%Y%m%d')
  url_info = URLInfo(project_name, report_date, PLATFORM, testing)

  build_steps = build_lib.project_image_steps(project_name,
                                              image,
                                              project_yaml['language'],
                                              branch=branch,
                                              test_images=test_images)

  out = build_project.get_out_dir(SANITIZER)
  env = build_lib.get_env(project_yaml['language'], FUZZING_ENGINE, SANITIZER,
                          ARCHITECTURE, out)

  build_lib.get_compile_step(project_name, env, image, FUZZING_ENGINE,
                             SANITIZER, ARCHITECTURE, dockerfile_lines)
  download_corpora_steps = build_lib.download_corpora_steps(project_name,
                                                            testing=testing)
  if not download_corpora_steps:
    logging.info('Skipping code coverage build for %s.', project_name)
    return []

  build_steps.extend(download_corpora_steps)

  failure_msg = ('*' * 80 + '\nCode coverage report generation failed.\n'
                 'To reproduce, run:\n'
                 f'python infra/helper.py build_image {project_name}\n'
                 'python infra/helper.py build_fuzzers --sanitizer coverage '
                 f'{project_name}\n'
                 f'python infra/helper.py coverage {project_name}\n' + '*' * 80)

  # Unpack the corpus and run coverage script.
  coverage_env = env + [
      'HTTP_PORT=',
      f'COVERAGE_EXTRA_ARGS={project_yaml["coverage_extra_args"].strip()}',
  ]
  if 'dataflow' in project_yaml['fuzzing_engines']:
    coverage_env.append('FULL_SUMMARY_PER_TARGET=1')

  build_steps.append({
      'name': f'gcr.io/{image_info.base_images_project}/base-runner',
      'env': coverage_env,
      'args': [
          'bash', '-c',
          ('for f in /corpus/*.zip; do unzip -q $f -d ${f%%.*} || ('
           'echo "Failed to unpack the corpus for $(basename ${f%%.*}). '
           'This usually means that corpus backup for a particular fuzz '
           'target does not exist. If a fuzz target was added in the last '
           '24 hours, please wait one more day. Otherwise, something is '
           'wrong with the fuzz target or the infrastructure, and corpus '
           'pruning task does not finish successfully." && exit 1'
           '); done && coverage || (echo "' + failure_msg + '" && false)')
      ],
      'volumes': [{
          'name': 'corpus',
          'path': '/corpus'
      }],
  })

  # Upload the report.
  upload_report_url = url_info.get_upload_url('reports')

  # Delete the existing report as gsutil cannot overwrite it in a useful way due
  # to the lack of `-T` option (it creates a subdir in the destination dir).
  build_steps.append(build_lib.gsutil_rm_rf_step(upload_report_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(out, 'report'),
          upload_report_url,
      ],
  })

  # Upload the fuzzer stats. Delete the old ones just in case.
  upload_fuzzer_stats_url = url_info.get_upload_url('fuzzer_stats')

  build_steps.append(build_lib.gsutil_rm_rf_step(upload_fuzzer_stats_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(out, 'fuzzer_stats'),
          upload_fuzzer_stats_url,
      ],
  })

  # Upload the fuzzer logs. Delete the old ones just in case
  upload_fuzzer_logs_url = url_info.get_upload_url('logs')
  build_steps.append(build_lib.gsutil_rm_rf_step(upload_fuzzer_logs_url))
  build_steps.append({
      'name':
          'gcr.io/cloud-builders/gsutil',
      'args': [
          '-m',
          'cp',
          '-r',
          os.path.join(out, 'logs'),
          upload_fuzzer_logs_url,
      ],
  })

  # Upload srcmap.
  srcmap_upload_url = url_info.get_upload_url('srcmap')
  srcmap_upload_url = srcmap_upload_url.rstrip('/') + '.json'
  build_steps.append({
      'name': 'gcr.io/cloud-builders/gsutil',
      'args': [
          'cp',
          '/workspace/srcmap.json',
          srcmap_upload_url,
      ],
  })

  # Update the latest report information file for ClusterFuzz.
  latest_report_info_url = build_lib.get_signed_url(
      url_info.latest_report_info_url,
      content_type=LATEST_REPORT_INFO_CONTENT_TYPE)
  latest_report_info_body = json.dumps({
      'fuzzer_stats_dir':
          upload_fuzzer_stats_url,
      'html_report_url':
          url_info.html_report_url,
      'report_date':
          report_date,
      'report_summary_path':
          os.path.join(upload_report_url, PLATFORM, 'summary.json'),
  })

  build_steps.append(
      build_lib.http_upload_step(latest_report_info_body,
                                 latest_report_info_url,
                                 LATEST_REPORT_INFO_CONTENT_TYPE))
  return build_steps


def main():
  """Build and run coverage for projects."""
  args = build_project.get_args('Generates coverage report for project.')
  logging.basicConfig(level=logging.INFO)
  image_info = build_project.ImageInfo('oss-fuzz', 'oss-fuzz-base')

  for project in args.projects:
    logging.info('Getting steps for: "%s".', project)
    steps = get_build_steps(project,
                            image_info,
                            testing=args.testing,
                            test_images=args.test_images,
                            branch=args.branch)

    build_project.run_build(steps, project, COVERAGE_BUILD_TAG)


if __name__ == "__main__":
  main()
