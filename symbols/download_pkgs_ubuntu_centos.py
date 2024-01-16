#!/usr/bin/python

# script to download debug packages of the relevant kernels

import re
import os

BASEURL_UB = "http://ddebs.ubuntu.com/ubuntu/pool/main/l/linux"
#BASEURL_CO = "http://mirror.centos.org/centos/"

# some kernels are gone from the official repo for whatever reason
BASEURL_CO = "http://mirrors.oit.uci.edu/centos/"


os.system("rm -rf tmp;wget -c -O tmp -- '%s' 2>/dev/null" % BASEURL_CO)

data = open("tmp").read()

urls = []

rels = re.findall('<a href="(8.*?)"', data)

for rel in rels:
	url = "%s%sBaseOS/x86_64/os/Packages/" % (BASEURL_CO, rel)
	print url
	os.system("rm tmp;wget -c -O tmp -- '%s' 2>/dev/null" % url)
	data = open("tmp").read()
	pkgs = re.findall('<a href="(kernel-core.*?)"', data)
	for pkg in pkgs:
		urls.append(url + "/" + pkg)

for url in urls:
	os.system("wget -c -- '%s'" % url)

os.system("rm linux;wget -c -- '%s' 2>/dev/null" % BASEURL_UB)

data = open("linux").read()

pkgs = re.findall(">(linux-image-unsigned-4\\.(?:18|15).0-.*?-generic-dbgsym_.*?_amd64.ddeb)", data)
pkgs += re.findall(">(linux-image-unsigned-5\\.(?:0|3|4)\\..*?-generic-dbgsym_.*?_amd64.ddeb)", data)

for pkg in pkgs:
	os.system("wget -c -- '%s/%s'" % (BASEURL_UB, pkg))

os.unlink("linux")
