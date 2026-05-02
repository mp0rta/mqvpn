mqvpn for Windows - quickstart

Requirements:
  - Windows 10 or 11, amd64 or arm64
  - (No additional runtime needed: this binary statically links the C runtime.)

Files in this archive (keep them together in one directory):
  mqvpn.exe              client binary
  xquic.dll              QUIC engine, dynamically linked
  wintun.dll             TUN device driver, runtime-loaded by mqvpn.exe
  LICENSE.wintun.txt     wintun's license terms
  README.windows.txt     this file
  client.conf.example    sample client configuration

Quick verification:
  .\mqvpn.exe --help

Note: only the client is supported on Windows. The server is Linux-only.

For full documentation: https://github.com/mp0rta/mqvpn
