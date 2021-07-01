#! /bin/bash

# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Clone, compile, and install system-wide the libbpf library

git clone https://github.com/libbpf/libbpf
cd libbpf
# This is the version of libbpf that our project has been tested with
# so far.
git checkout 1339ef70a36f8013af12365998e8805df57519ba
cd src
make
sudo make install
echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/libbpf.conf > /dev/null
sudo ldconfig
