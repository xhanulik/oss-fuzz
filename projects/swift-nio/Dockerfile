# Copyright 2021 Google LLC
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

FROM gcr.io/oss-fuzz-base/base-builder

# generic swift
RUN apt-get update && apt-get install -y wget \
           binutils \
           libc6-dev \
           libcurl4 \
           libgcc-9-dev \
           libedit2 \
           libtinfo5 \
           libpython3.8 \
           libsqlite3-0 \
           libstdc++-9-dev \
           libxml2 \
           pkg-config \
           libz3-dev \
           tzdata \
           zlib1g-dev

ENV SWIFT_RELEASE=swift-5.4.2-RELEASE-ubuntu20.04
RUN wget -q https://swift.org/builds/swift-5.4.2-release/ubuntu2004/swift-5.4.2-RELEASE/$SWIFT_RELEASE.tar.gz
RUN tar xzf $SWIFT_RELEASE.tar.gz
RUN cp -r $SWIFT_RELEASE/usr/* /usr/

# generic swift symbolizer
RUN apt-get update && apt-get install -y build-essential make cmake ninja-build git python3 g++-multilib binutils-dev zlib1g-dev --no-install-recommends
RUN git clone --depth 1 https://github.com/llvm/llvm-project.git
COPY llvmsymbol.diff $SRC

# specific swift-nio
RUN git clone --depth 1 https://github.com/google/fuzzing
RUN git clone --depth 1 https://github.com/apple/swift-nio.git
COPY build.sh $SRC
COPY *.swift $SRC/
WORKDIR $SRC/swift-nio
