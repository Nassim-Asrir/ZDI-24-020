#!/usr/bin/python

import glob
import os
import re

def get_structs(fn, structs):
	cmds = []
	for struct in structs:
		cmds.append("-ex 'ptype /o struct %s'" % struct)

	cmds.append("-ex 'q'")
	cmds = " ".join(cmds)

	cmd = "gdb -q -ex 'set confirm off' -ex 'set pagination off' --nx %s -- %s" % (cmds, fn)
	data = os.popen(cmd).read()

	return data

def get_offsets(ver, fn, symbols):
	cmds = []
	for sym in symbols:
		cmds.append("-ex 'x/bx &%s'" % sym)

	cmds.append("-ex 'q'")
	cmds = " ".join(cmds)

	cmd = "gdb -q -ex 'set confirm off' -ex 'set pagination off' --nx %s -- %s" % (cmds, fn)
	data = os.popen(cmd).read()

	# 'Reading symbols from ./usr/lib/debug/boot/vmlinux-4.18.0-19-generic...done.\n0xffffffff826cc180 <startup_xen>:\t0xfc\n0xffffffff811e3ac0 <__rb_free_aux>:\t0xe8\n0xffffffff8121dbc0 <kmem_cache_size>:\t0xe8\n0xffffffff8245b160 <init_cred>:\t0x04\n0xffffffff810b6540 <override_creds>:\t0xe8\n'

	m = re.findall("0x([0-9a-f]+) <(.*?)>:", data)

	symoffs = {}

	for k, v in m:
		symoffs[v] = int(k, 16) - 0xffffffff81000000

		# avoid nullbytes in these
		if v in ("run_cmd", "__rb_free_aux") and symoffs[v] & 0xff == 0: symoffs[v] += 5

	# check that the string addr won't have a nullbyte
	assert ((symoffs["kernfs_pr_cont_buf"] + 224 + 8) & 0xff) != 0


	ret = '\t{"%s", ' % ver
	x = ["0x%.8x" % symoffs[s] for s in symbols]
	ret += ", ".join(x)
	ret += "},\n"

	return ret

def check_struct_offsets(structs):
	s = structs["gsm_mux"]

	assert s["output"][0] == 144
	assert s["encoding"][0] == 108

	s = structs["gsm_dlci"]

	assert s["gsm"][0] == 0
	assert s["timer_list"][0] == 56

	# name changed in some newer 5.x kernels
	if "ring_buffer" in structs:
		s = structs["ring_buffer"]
	else:
		s = structs["perf_buffer"]

	assert s["free_aux"][0] == 200
	assert s["aux_priv"][0] == 224



def parse_structs(data):
	curstruct = None
	curname = None
	structs = {}

	for l in data.splitlines():
		start = re.findall("type = struct (.*?) {", l)

		if start:
			if curstruct:
				structs[curname] = curstruct
			curname = start[0]
			curstruct = {}
			continue

		m = re.findall(r"/\*[ ]+(.*?) .*?\|[ ]+(.*?) .*?\*/    [a-zA-Z]", l)
		if not m: continue
		offset, size = m[0]
		offset = int(offset)
		size = int(size)
		if "(*" in l:
			name = re.findall(r"\(*([a-zA-Z0-9_]+)\)\(", l)[0]
		else:
			l = l.split()

			if l[-1] == "{":
				name = l[-2]
			else:
				name = re.findall("[a-zA-Z0-9_]+", l[-1])
				name = name[0]

		curstruct[name] = (offset, size)

	structs[curname] = curstruct

	return structs



def natsort(l):
        conv = lambda text: int(text) if text.isdigit() else text.lower()
        alnum_key = lambda key: [conv(c) for c in re.split(r'(\d+)', key)]
        return sorted(l, key=alnum_key, reverse=True)

fns = glob.glob("*.ddeb")
fns = natsort(fns)

out = ""

for i, fn in enumerate(fns):

	os.system("rm -rf tmp; mkdir tmp")
	os.chdir("tmp")

	print "Checking %s (%u/%u)" % (fn, i+1, len(fns))

	# linux-image-unsigned-4.18.0-19-generic-dbgsym_4.18.0-19.20_amd64.ddeb
	ver = re.findall("linux-image-unsigned-(.*)-dbgsym", fn)[0]

	# no need to check data.tar.<ext>, they are all xz now
	p1 = "./usr/lib/debug/lib/modules/%s/kernel/drivers/tty/n_gsm.ko" % ver
	p2 = "./usr/lib/debug/boot/vmlinux-%s" % ver

	os.system("ar p '../%s' data.tar.xz|tar Jxf - %s %s" % (fn, p1, p2))

	try:
		structs = get_structs(p1, ("gsm_dlci", "gsm_mux"))
		structs += get_structs(p2, ("ring_buffer", ))
		structs += get_structs(p2, ("perf_buffer", ))

		structs = parse_structs(structs)

		check_struct_offsets(structs)

	except:
		print "FAIL", fn
		os.chdir("..")

		continue


	out += get_offsets(ver, p2, ("xen_hypercall_set_trap_table", "run_cmd", "kernfs_pr_cont_buf", "__rb_free_aux", "kmem_cache_size"))

	os.chdir("..")


print out
