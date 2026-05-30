# Wintun userspace header

`wintun.h` is the userspace API header for the Wintun TUN driver, developed
and published by WireGuard LLC at https://www.wintun.net.

## License

Wintun's userspace header is dual-licensed under `GPL-2.0 OR MIT`.
**mqvpn selects the MIT license**, distributed in `LICENSE` in this directory.

## Runtime driver

The runtime driver (`wintun.dll`) is not bundled in mqvpn source distributions.
Windows binary releases download `wintun.dll` from https://www.wintun.net at
build time. The DLL is distributed by WireGuard LLC under its own terms.
