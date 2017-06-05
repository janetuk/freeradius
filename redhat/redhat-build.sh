#! /bin/bash

# This script should be run inside of a moonshot directory that contains 
# a freeradius-server repository.

# Usage: rhb.sh <freeradius-version>
# <freeradius-version> should include any moonshot extensions, e.g.: 3.0.13-5

set -euo pipefail
IFS=$'\n\t'

VERSION=$1
# echo "VERSION is: " 
# Clean the old source directory
rm -rf freeradius-${VERSION}

# Copy the git root to the source root
cp -a freeradius-server freeradius-${VERSION}

# Compress
# tar -zcf freeradius-${VERSION}.tar.gz freeradius-${VERSION}
tar -zcf freeradius-${VERSION}.tar.gz freeradius-server

# Move new source package
cp freeradius-${VERSION}.tar.gz ~/rpmbuild/SOURCES/freeradius-server.tar.gz
mv -f freeradius-${VERSION}.tar.gz ~/rpmbuild/SOURCES/
cp rpm-sources/* ~/rpmbuild/SOURCES

# Move new spec file
cp freeradius-server/freeradius-server.spec ~/rpmbuild/SPECS/

# Build SRPM
rpmbuild -bs ~/rpmbuild/SPECS/freeradius-server.spec

# Build RPM
# /usr/bin/mock -r moonshot-7-x86_64 rpmbuild/SRPMS/freeradius-${VERSION}-3.el7.centos.src.rpm
# rpmbuild -bb ~/rpmbuild/SRPMS/freeradius-${VERSION}.el7.centos.src.rpm
rpmbuild --rebuild  ~/rpmbuild/SRPMS/freeradius-${VERSION}.el7.centos.src.rpm 

# Copy to server
#scp /var/lib/mock/epel-7-x86_64/result/*.rpm root@server:/path
