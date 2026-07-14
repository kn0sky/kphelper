from pathlib import Path

from .errors import KpcliError
from .pwn import log


EXP_C_TEMPLATE = r'''#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEVICE_PATH "/dev/xxx"

static unsigned long user_cs;
static unsigned long user_ss;
static unsigned long user_sp;
static unsigned long user_rflags;

static void save_state(void) {
    __asm__(
        "mov %%cs, %0\n"
        "mov %%ss, %1\n"
        "mov %%rsp, %2\n"
        "pushfq\n"
        "pop %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_sp), "=r"(user_rflags)
        :
        : "memory"
    );
}

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static int open_dev(void) {
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0) {
        die("open " DEVICE_PATH);
    }
    return fd;
}

static void get_shell(void) {
    puts("[+] returned to userland");
    if (getuid() == 0) {
        execl("/bin/sh", "sh", NULL);
        execl("/bin/ash", "sh", NULL);
    }
    puts("[-] not root");
    exit(EXIT_FAILURE);
}

int main(void) {
    save_state();
    int fd = open_dev();

    /*
     * Common kernel ROP targets:
     *   commit_creds(prepare_kernel_cred(NULL))
     *
     * Common trampoline tail:
     *   swapgs; iretq;
     *   rip = get_shell
     *   cs = user_cs
     *   rflags = user_rflags
     *   rsp = user_sp
     *   ss = user_ss
     *
     * Fill gadget and symbol addresses after checking KASLR and leaks.
     */

    /*
     * Common primitives to consider:
     *   - msg_msg heap spray / arbitrary read-write shaping
     *   - userfaultfd or FUSE pause for race/window widening
     *   - modprobe_path overwrite when available
     *   - seq_operations / tty_struct / pipe_buffer pivots by kernel version
     */

    (void)fd;
    puts("[*] TODO: trigger vulnerability");
    return 0;
}
'''


def write_exp_template(path="exp.c", force=False):
    path = Path(path)
    if path.exists() and not force:
        raise KpcliError("%s already exists; use --force to overwrite" % path)
    path.write_text(EXP_C_TEMPLATE)
    log.success("created %s", path)
    return path
