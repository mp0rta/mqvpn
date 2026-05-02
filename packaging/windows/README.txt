mqvpn for Windows - quickstart
================================

Requirements
------------
  - Windows 10 or 11, amd64 or arm64
  - Administrator privileges (required for Wintun TUN device, routing, and
    firewall changes)
  - PowerShell (recommended; cmd.exe also works)
  - No additional runtime needed: this binary statically links the C runtime.

Files in this archive (keep them together in one directory)
-----------------------------------------------------------
  mqvpn.exe                       client binary (Apache 2.0)
  xquic.dll                       QUIC engine, dynamically linked
  wintun.dll                      TUN device driver, runtime-loaded
  README.txt                      this file
  LICENSE                         mqvpn license (Apache 2.0)
  THIRD_PARTY_LICENSES/
    xquic.txt                     xquic (Apache 2.0)
    boringssl.txt                 BoringSSL (Apache 2.0 / ISC), linked into xquic.dll
    libevent.txt                  libevent (BSD-3-Clause), linked into xquic.dll
    wintun.txt                    wintun (WireGuard LLC license)

Step 1: open an Administrator PowerShell
----------------------------------------
  Right-click PowerShell -> "Run as Administrator"
  cd to the folder where you extracted this archive.

  Verify the binary loads:
    .\mqvpn.exe --help

Step 2: list your network adapters
----------------------------------
  --path requires the adapter FriendlyName as shown by Get-NetAdapter:

    Get-NetAdapter | Where-Object Status -eq 'Up' | Select Name, InterfaceDescription

  Use the value in the "Name" column (e.g. "Ethernet", "Wi-Fi",
  "イーサネット 3"). Quote names that contain spaces.

Step 3: connect
---------------
  Single path:
    .\mqvpn.exe --mode client `
      --server vpn.example.com:443 `
      --auth-key <YOUR_PSK> `
      --path "Ethernet"

  Multipath (multiple NICs aggregated):
    .\mqvpn.exe --mode client `
      --server vpn.example.com:443 `
      --auth-key <YOUR_PSK> `
      --path "Ethernet" --path "Wi-Fi" `
      --scheduler wlb

  Common options:
    --dns 1.1.1.1 --dns 8.8.8.8     set DNS servers (repeatable, max 4)
    --kill-switch                    block traffic outside the tunnel
    --tun-name mqvpn0                TUN device name (default mqvpn0)
    --log-level debug                more verbose logging
    --insecure                       accept untrusted certs (testing only)

  Stop with Ctrl+C.

Using a config file (optional)
------------------------------
  Instead of CLI flags you can pass --config:

    .\mqvpn.exe --config .\client.conf

  See systemd/client.conf.example in the repo for the INI format. On
  Windows the [Multipath] Path = ... values are adapter FriendlyNames
  (not "eth0" / "wlan0").

Notes and limitations
---------------------
  - Only the client is supported on Windows. The server is Linux-only.
  - --path is required on Windows (specify at least one adapter).
  - On legacy CP932-only consoles, non-ASCII adapter names may be garbled
    during interface lookup; rename the adapter to ASCII or run from a
    UTF-8 capable terminal (Windows Terminal / PowerShell 7+).

For full documentation: https://github.com/mp0rta/mqvpn
