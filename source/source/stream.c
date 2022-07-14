#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "seccomp-bpf.h"

#define PTR_MANGLE(var)   __asm__("xor %%fs:0x30, %0; rol $0x11, %0" : "=r" (var) : "0" (var));
#define PTR_DEMANGLE(var) __asm__("ror $0x11, %0; xor %%fs:0x30, %0" : "=r" (var) : "0" (var));

#define LIST_LEN    0x10
#define MAX_BUF_LEN 0x200

struct cookie_struct {
    char*   buffer;
    size_t  size;
    off64_t pos;
    off64_t maxpos;
};

struct cookie_struct* COOKIE_JAR_PTR;
uint64_t COOKIE_JAR_ALLOC_MAP;

FILE* STREAM_LIST[LIST_LEN];

char BUFFER[MAX_BUF_LEN];

void print(char* s)
{
    write(1, s, strlen(s));
}

int readint()
{
    char buf[16];
    memset(buf, 0, sizeof(buf));
    read(0, buf, 16);
    return atoi(buf);
}

void audit_24(uint32_t x) {
    char buf[8];
    print("[AUDIT] ");
    for(int i = 3; i > 0; --i) {
        buf[i-1] = "0123456789ABCDEF"[x & 0xF];
        x >>= 4;
    }
    buf[3] = '\n';
    buf[4] = '\x00';
    print(buf);
}

static inline __attribute__((always_inline)) int ctz_64(uint64_t x)
{
	__asm__("bsf %1, %0" : "=r"(x) : "r"(x));
	return x;
}

void init_seccomp()
{
    struct sock_filter filter[] = {
        VALIDATE_ARCHITECTURE2(9),
        EXAMINE_SYSCALL,
        ALLOW_SYSCALL2(open, 6),
        ALLOW_SYSCALL2(read, 5),
        ALLOW_SYSCALL2(write, 4),
        ALLOW_SYSCALL2(getrandom, 3),
        ALLOW_SYSCALL2(brk, 2),
        ALLOW_SYSCALL2(exit, 1),
        ALLOW_SYSCALL3(exit_group, 1),
        ALLOW_PROCESS,
        KILL_PROCESS,
    };
    struct sock_fprog prog = {
        .len  = sizeof(filter)/sizeof(struct sock_filter),
        .filter = filter,
    };
    if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
    {
    	perror("prctl(NO_NEW_PRIVS)");
        _exit(-1);
    }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
    {
	    perror("prctl(SECCOMP)");
        _exit(-1);
    }
}

void init_cookie_jar()
{
    int fd;
    void* ptr = NULL;
    if ((fd = open("/dev/urandom", O_RDONLY)) == -1) {
        print("[-] failed to open /dev/urandom!\n");
        _exit(-1);
    }
    while (1)
    {
        read(fd, &ptr, 5);
        ptr = (void*)((uint64_t)ptr & ~0xFFF);
        if (mmap(ptr, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == ptr)
            break; 
    }
    close(fd);
    COOKIE_JAR_PTR  = (struct cookie_struct*) ptr;
    COOKIE_JAR_ALLOC_MAP = (uint64_t)-1;
    ptr = NULL;
}

struct cookie_struct* alloc_cookie()
{
    if (!COOKIE_JAR_ALLOC_MAP)
        return NULL;
    int idx = ctz_64(COOKIE_JAR_ALLOC_MAP);
    COOKIE_JAR_ALLOC_MAP &= ~(1ul << idx);
    return &(COOKIE_JAR_PTR[idx]);
}

void dealloc_cookie(struct cookie_struct* c)
{
    if ((uint64_t)c % sizeof(struct cookie_struct) != 0)
        return;
    int idx = c - &(COOKIE_JAR_PTR[0]);
    if (idx < 0 || idx >= 8 * sizeof(uint64_t))
        return;
    COOKIE_JAR_ALLOC_MAP |= 1ul << idx;
    memset(c, 0, sizeof(struct cookie_struct));
}

ssize_t stream_read(void *cookie, char *b, size_t s)
{
    PTR_DEMANGLE(cookie);
    struct cookie_struct *c = (struct cookie_struct *) cookie;
    if ((size_t) c->pos + s > c->maxpos) {
        if ((size_t) c->pos > c->size)
            return 0;
        s = c->maxpos - c->pos + 1;
    }
    memcpy(b, &(c->buffer[c->pos]), s);
    c->pos += s;
    return s;
}

ssize_t stream_write(void *cookie, const char *b, size_t s)
{
    PTR_DEMANGLE(cookie);
    struct cookie_struct *c = (struct cookie_struct *) cookie;
    if ((size_t) c->pos + s > c->size) {
        if ((size_t) c->pos > c->size)
            return 0;
        s = c->size - c->pos + 1; // BUG
    }
    memcpy(&(c->buffer[c->pos]), b, s);
    c->pos += s;
    if ((size_t) c->pos > c->maxpos)
        c->maxpos = c->pos;
    return s;
}

int stream_seek(void *cookie, off64_t *p, int w)
{
    PTR_DEMANGLE(cookie);
    struct cookie_struct *c = (struct cookie_struct *) cookie;
    off64_t np;
    switch(w)
    {
        case SEEK_SET:
            np = *p; break;
        case SEEK_CUR:
            np = c->pos + *p; break;
        case SEEK_END:
            np = c->size + *p; break;
        default:
            return -1;
    }
    if (np < 0 || (size_t) np > c->size)
        return -1;
    *p = c->pos = np;
    return 0;
}

int stream_close(void *cookie)
{
    PTR_DEMANGLE(cookie);
    struct cookie_struct *c = (struct cookie_struct *) cookie;
    free(c->buffer);
    dealloc_cookie(c);
    return 0;
}

const cookie_io_functions_t STREAM_IOF = {
    .read  = stream_read,
    .write = stream_write,
    .seek  = stream_seek,
    .close = stream_close,
};

FILE* stream_open(size_t size, const char *mode)
{
    struct cookie_struct *c, *mc;
    FILE *fp;
    if ((mc = c = alloc_cookie()) == NULL) {
        print("[-] failed to allocate cookie!\n");
        return NULL;
    }
    if ((c->buffer = (char *)calloc(size, 1)) == NULL) {
        print("[-] failed to allocate buffer!\n");
        dealloc_cookie(c);
        return NULL;
	}
    audit_24((uint64_t)c->buffer & 0xFFF);
    c->size = size;
    if (mode[0] == 'r')
        c->maxpos = c->size;
    PTR_MANGLE(mc);
    if ((fp = fopencookie(mc, mode, STREAM_IOF)) == NULL) {
        print("[-] fopencookie() failed!\n");
        free(c->buffer);
        dealloc_cookie(c);
        return NULL;
    }
    return fp;
}

void do_open() {
    char* mode;
    FILE* fp;
    size_t size;
    int idx;
    print("[*] What is the index?: ");
    idx = readint();
    if (idx < 0 || idx >= LIST_LEN) {
        print("[-] invaild index\n");
        return;
    }
    print("[*] What type of stream do you want to create? (0 for readable or 1 for writable): ");
    switch(readint())
    {
        case 0:
            mode = "r+"; break;
        case 1:
            mode = "w+"; break;
        default:
            print("[-] invaild type\n");
            return;
    }
    print("[*] How large the stream buffer will be?: ");
    size = readint();
    if (size == 0 || size > MAX_BUF_LEN) {
        print("[-] invaild buffer size\n");
        return;
    }
    if ((fp = stream_open(size, mode)) == NULL) {
        print("[-] stream_open() failed!\n");
        return;
    }
    setvbuf(fp, NULL, _IONBF, 0);
    rewind(fp);
    STREAM_LIST[idx] = fp;
    print("[+] Done\n");
}

void do_read() {
    size_t size;
    int idx;
    memset(BUFFER, 0, sizeof(BUFFER));
    print("[*] What is the index?: ");
    idx = readint();
    if (idx < 0 || idx >= LIST_LEN || !STREAM_LIST[idx]) {
        print("[-] invaild index\n");
        return;
    }
    print("[*] How long do you want to read?: ");
    size = readint();
    if (size > MAX_BUF_LEN) {
        print("[-] too long\n");
        return;
    }
    for(int readn = 0; readn < size; ++readn)
    {
        if (fread(&BUFFER[readn], 1, 1, STREAM_LIST[idx]) != 1) {
            print("[!] fread() failed!\n");
            return;
        }
    }
    print("[+] Data: ");
    write(1, BUFFER, size);
    print("\n[+] Done\n");
}

void do_write() {
    size_t size;
    int idx;
    memset(BUFFER, 0, sizeof(BUFFER));
    print("[*] What is the index?: ");
    idx = readint();
    if (idx < 0 || idx >= LIST_LEN || !STREAM_LIST[idx]) {
        print("[-] invaild index\n");
        return;
    }
    print("[*] How long do you want to write?: ");
    size = readint();
    if (size > MAX_BUF_LEN) {
        print("[-] too long\n");
        return;
    }
    print("[*] Data: ");
    read(0, BUFFER, size);
    for(int writen = 0; writen < size; ++writen)
    {
        if (fwrite(&BUFFER[writen], 1, 1, STREAM_LIST[idx]) != 1) {
            print("[!] fwrite() failed!\n");
            return;
        }
    }
    print("[+] Done\n");
}

void do_seek() {
    int idx;
    int whence;
    off64_t offset;
    print("[*] What is the index?: ");
    idx = readint();
    if (idx < 0 || idx >= LIST_LEN || !STREAM_LIST[idx]) {
        print("[-] invaild index\n");
        return;
    }
    print("[*] What is the whence? (0 for SEEK_SET, 1 for SEEK_CUR or 2 for SEEK_END): ");
    whence = readint();
    if (whence > 2) {
        print("[-] invaild whence\n");
        return;
    }
    print("[*] What is the offset?: ");
    offset = readint();
    if (fseek(STREAM_LIST[idx], offset, whence) == 0) {
        print("[+] Done\n");
    } else {
        print("[-] fseek() failed!\n");
    }
}

void do_close() {
    int idx;
    print("[*] What is the index?: ");
    idx = readint();
    if (idx < 0 || idx >= LIST_LEN || !STREAM_LIST[idx]) {
        print("[-] invaild index\n");
        return;
    }
    fclose(STREAM_LIST[idx]);
    STREAM_LIST[idx] = NULL;
    print("[+] Done\n");
}

void menu()
{
    print("🌊 Stream: A lite program to have fun with the powerful FILE stream\n");
    print("Menu: \n");
    print("  0. 🟢 Open a new stream\n");
    print("  1. ❌ Close an existing stream\n");
    print("  2. ➡️  Read from a stream\n");
    print("  3. ⬅️  Write to a stream\n");
    print("  4. 👀 Seek a stream\n");
    print("  5. 🚪 Exit this program\n");
    print("[*] >> ");
}

int main()
{
    init_cookie_jar();
    init_seccomp();
    while (1)
    {
        menu();
        switch(readint())
        {
            case 0:
                do_open(); break;
            case 1:
                do_close(); break;
            case 2:
                do_read(); break;
            case 3:
                do_write(); break;
            case 4:
                do_seek(); break;
            case 5:
                _exit(0);
            default:
                print("[!] undefined command\n");
        }
    }

}
