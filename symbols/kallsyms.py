import os

# script to get symbols from kallsyms

ls = open("/proc/kallsyms").readlines()

addrs = {}

for l in ls:
	l = l.split()
	l = l[:3]
	addr, type, name = l
	addrs[name] = int(addr, 16)


hm = []
for s in ("hypercall_page", "run_cmd", "kernfs_pr_cont_buf", "__rb_free_aux", "kmem_cache_size", "commit_creds", "init_cred"):
	addr = 0
	if s in addrs:
		addr = addrs[s] - addrs["_text"]
		if addr & 0xff == 0 and s in ("run_cmd", "__rb_free_aux", "commit_creds"): addr += 5
	hm.append(addr)

out = "\t{"
out += '"%s", ' % os.popen("uname -r").read().strip()
out += ", ".join(["0x%lx" % x for x in hm])

out += "},"

print(out)

