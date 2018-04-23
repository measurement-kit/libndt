#!/bin/sh
set -ex
venv=.mk-python-virtual-env
rm -rf $venv
virtualenv $venv
. $venv/bin/activate
pip install conan
conan install --build=missing .
