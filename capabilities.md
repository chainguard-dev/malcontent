Formulation:
============

category/resource/<action>

transform/base64/encode
transform/xor/decode

meta/project/id
meta/format
meta/compiler/kind
meta/compiler/version
meta/author/apple
meta/usage
meta/signature/id

data/certificate
data/base64
data/...

net/ip
net/udp
net/tcp
net/icmp
net/tcp/http

net/socket/bind
    bind (syscall)
net/socket/send
    send, sendmsg, sendto
net/addr/resolve
    - gethostbyaddr
    - inet_addr, inet_aton
net/name/resolve
    - gethostbyname2

net/interface/list
    - getfreeifaddrs (libc)

proc/pid/get
    - getpid
proc/uid/set
    - setuid

proc/create
proc/thread/create


signal/mask/set

clock/system/get
    - gettimeofday
    - localtime
clock/system/set
    - settimeofday

io/select
    _select


fs/hier/traverse
fs/hier/list
fs/inode/modify
fs/??

kernel/controls/ref:
kernel/controls/set
kernel/controls/get

kernel/dev/...



tags:
