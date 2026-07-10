mqvpn for macOS - quickstart
==============================

Requirements
------------
  - macOS on Apple silicon (arm64)
  - Root privileges (sudo; required for the utun TUN device, routing, and
    DNS changes)
  - No additional runtime needed: xquic, BoringSSL and libevent are
    statically linked into the binary.

Files in this archive (keep them together in one directory)
-----------------------------------------------------------
  mqvpn                           client binary (Apache 2.0)
  client.conf.example             sample configuration file (INI format)
  README.txt                      this file
  LICENSE                         mqvpn license (Apache 2.0)
  NOTICE                          mqvpn and third-party attribution notices
  third-party/
    xquic.txt                     xquic (Apache 2.0), statically linked
    boringssl.txt                 BoringSSL (Apache 2.0 / ISC), statically linked
    libevent.txt                  libevent (BSD-3-Clause), statically linked

Step 1: allow the unsigned binary
---------------------------------
  The binary is not code-signed or notarized. If you downloaded the
  archive with a browser, Gatekeeper quarantines it; clear the flag:

    xattr -d com.apple.quarantine mqvpn

  (Not needed when fetched with curl/wget.) Then verify it runs:

    ./mqvpn --help

Step 2: list your network interfaces
------------------------------------
  --path takes BSD interface names (en0, en1, ...). To map them to
  hardware:

    networksetup -listallhardwareports

  or check which interfaces are up:

    ifconfig -u | grep -E '^en[0-9]+:'

Step 3: connect
---------------
  Single path:
    sudo ./mqvpn --mode client \
      --server vpn.example.com:443 \
      --auth-key <YOUR_PSK> \
      --path en0

  Multipath (e.g. Wi-Fi + USB Ethernet aggregated):
    sudo ./mqvpn --mode client \
      --server vpn.example.com:443 \
      --auth-key <YOUR_PSK> \
      --path en0 --path en7 \
      --scheduler wlb

  Common options:
    --dns 1.1.1.1 --dns 8.8.8.8     set DNS servers (repeatable, max 4)
    --kill-switch                    block traffic outside the tunnel
    --log-level debug                more verbose logging
    --insecure                       accept untrusted certs (testing only)

  Stop with Ctrl+C.

Using a config file (optional)
------------------------------
  Instead of CLI flags you can pass --config:

    sudo ./mqvpn --config ./client.conf

  See the bundled client.conf.example for the INI format. On macOS the
  [Multipath] Path = ... values are BSD interface names (en0, en1, ...).

Notes and limitations
---------------------
  - Only the client is supported on macOS. The server is Linux-only.
  - macOS assigns utun device names itself: the tunnel comes up as
    utunN (shown in the logs), not as the --tun-name default mqvpn0.
    Pass --tun-name utunN to request a specific unit.

For full documentation: https://github.com/mp0rta/mqvpn
