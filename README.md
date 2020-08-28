![C/C++ CI](https://github.com/current/loader-old/workflows/C/C++%20CI/badge.svg)
# Preface
Loader is a fully featured remote image loader, with a windows client and a linux server, only windows x64bit is supported because the current syscalls implementation only works on 64bit. 

# How to build
## server
```
mkdir build
cd build
cmake ..
build
```
## client
open the solution and build.

# Features
- communication using TLS 1.3 + small xor implementation.
- json client-server communication, packet struct implementation for easier parsing.
- support for Xenforo forum integration on the server.
- support for 32-64bit processes.
- syscalls.
- module patch detection.
- basic debugger detection.
- small gui.
- fast image streaming.
- relocations and imports done on server.
- support for multiple games.
- small client size.
- manual map everything, including dependencies.
- blacklist system.
- normal timeout/security packet timeout.
- unique client session ids.
- server certificate verification.
- client/server version control.

# Credits
- [linux-pe](https://github.com/can1357/linux-pe)
- [fmt](https://github.com/fmtlib/fmt)
- [mstl](https://gitlab.com/madddie/my-toolkit)
