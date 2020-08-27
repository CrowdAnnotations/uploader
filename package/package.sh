#!/bin/bash

# install requirements
pip install -r ./requirements.txt

# set environment
rm -rf ./dist ./build
mkdir ./dist ./build

# package
pushd ../
pyinstaller --onefile --workpath=./package/build --distpath=./package/dist --specpath=./package/dist -n ca_uploader ./uploader.py
popd

# copy dist to build (--onedir only)
# cp -r ./dist/ca_uploader/* ./build/ca_uploader