#!/usr/libexec/platform-python

# Run this on an RHEL system with an active subscription to download kernel packages to ./pkgs

import os
import re

data = os.popen("yum --showduplicate list kernel").read()

kerns = []

for l in data.splitlines():
	if "kernel.x86_64" not in l: continue
	l = l.split()
	ver = l[1]

	kern = "kernel-core-" + ver + ".x86_64"
	kerns.append(kern)


for kern in kerns:
	os.system("yes|yum --downloadonly install " + kern)
	os.system("yes|yum --downloadonly reinstall " + kern)


os.system("mkdir pkgs")
os.system("cp `find /var/cache/dnf -name 'kernel-core*'` pkgs/")
