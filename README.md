# stream

用 [fopencookie](https://man7.org/linux/man-pages/man3/fopencookie.3.html) 函数实现自定义回调函数的 IO 流，源码部分主要参考了 GLIBC 的 [fmemopen()](https://man7.org/linux/man-pages/man3/fmemopen.3.html) [实现](https://elixir.bootlin.com/glibc/glibc-2.35/source/libio/fmemopen.c)。

## 漏洞

Off-by-one。漏洞位于`write`操作中，当写入数据长度超出剩余空间时，可以越界写一字节。

```c
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
```

`read`操作也有一个类似的越界读一字节的漏洞，不过没什么用（摆设）。

## 保护

GLIBC 采用最新版本（2.35），同时破坏了[House of Emma](https://www.anquanke.com/post/id/260614)、[House of Banana](https://www.anquanke.com/post/id/222948)等绝大部分高版本堆利用手法的利用条件。

1. 全保护；
2. `seccomp`沙盒；
3. 使用`calloc`函数分配缓冲区；
4. 没有调用`exit`以及`printf`、`puts`等 IO 函数；
5. `mmap`一块随机地址内存区域`cookie`用于储存缓冲区指针；
6. 使用 `PTR_DEMANGLE`加密`cookie`指针（防止`__pointer_chk_guard`被覆写）；
7. 使用`fopencookie`创建流后，使用`rewind`调用`seek`操作（理由同上）；
8. 逐一字节地从 IO 流写入/读出数据（理由同上）；

## 利用思路

分为两个部分：劫持 `FILE`对象和 FSOP。

劫持 `FILE`对象十分简单，只需利用 off-by-one 漏洞修改 chunk size 形成 overlapping chunk，然后将 FILE 对象分配到 overlapping chunk 上面即可。由于程序只有`calloc`，需要将 overlapping chunk 合并到 top chunk 才可重用。

FSOP 需要利用一条能够劫持栈空间的路径：`_IO_wfile_underflow_mmap -> _IO_wdoallocbuf`。 <del>经过这几天的网上搜索，基本可以确定没有人发现（或者公布）这条 FSOP 路径</del>（**2022/8/24**：[现](https://bbs.pediy.com/thread-273895.htm)[在](https://bbs.pediy.com/thread-273863.htm)[就](https://www.xl-bit.cn/index.php/archives/839/)不是这样了）。

其中`_IO_wfile_underflow_mmap`能够将`rbp`寄存器设为任意地址，然后`_IO_wdoallocbuf`可以劫持控制流。因此只需构造好 payload，将控制流劫持到`leave; ret` gadget 上就能进行栈迁移了。

```c
static wint_t
_IO_wfile_underflow_mmap (FILE *fp)
{
  struct _IO_codecvt *cd;

  [...]

  if (__glibc_unlikely (fp->_flags & _IO_NO_READS))
    {
      __set_errno (EBADF);
      return WEOF;
    }
  if (fp->_wide_data->_IO_read_ptr < fp->_wide_data->_IO_read_end)
    return *fp->_wide_data->_IO_read_ptr;

  cd = fp->_codecvt;       <------------ mov rbp, qword ptr [rdi+0x89]

  [...]

  if (fp->_wide_data->_IO_buf_base == NULL)
    {
      /* Maybe we already have a push back pointer.  */
      if (fp->_wide_data->_IO_save_base != NULL)
    {
      free (fp->_wide_data->_IO_save_base);
      fp->_flags &= ~_IO_IN_BACKUP;
    }
      _IO_wdoallocbuf (fp); <----------- Go to next hop
    }

  [...]

}

void
_IO_wdoallocbuf (FILE *fp)
{
  if (fp->_wide_data->_IO_buf_base)
    return;
  if (!(fp->_flags & _IO_UNBUFFERED))
    if ((wint_t)_IO_WDOALLOCATE (fp) != WEOF) <------ mov rax, qword [rax+0xe0]; call qword [rax+0x68]
      return;

  [...]

}    
```


## 结果

<u>选中为 Day 1 赛题：无人解出，大概 30 支队伍 Patch 成功</u>（没仔细数，比赛途中看榜单才发现自己的题目被选上了）。

详细 Writeup 与修复思路见 [writup.md](./writup/writup.md)。

Xp0intJNU 的师傅发现一种非预期的修复方法：直接 NOP 掉 `do_open`函数里面的`setvbuf(fp, NULL, _IONBF, 0);`语句。这样的话`fread/fwrite`内部会[分配堆块](https://www.gnu.org/software/libc/manual/html_node/Controlling-Buffering.html)用作缓冲区，改变了堆布局，导致 EXP 打不通。

**P.S.**  `_IO_wfile_underflow_mmap` 调用链是使用 [Binary Ninja](https://binary.ninja) 插件 [fsop-finder](https://github.com/xf1les/fsop-finder) 找到的。


## License

The MIT License (MIT)
