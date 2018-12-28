#!/bin/bash

mkdir -p ./rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} || exit 1
cp patches/*.patch ./rpmbuild/SOURCES/ || exit 1
cp specs/*.spec ./rpmbuild/SPECS/ || exit 1
