# Privacy Policy — mqvpn Android app

*Effective date: 2026-08-24*

This policy covers the mqvpn Android application (`org.mqvpn.app`), published
by Vortric Labs.

## What we collect

Nothing. Apart from the VPN traffic described below, mqvpn does not collect
or transmit personal data, usage data, analytics, telemetry, or crash reports
to Vortric Labs or to any service operated by Vortric Labs. The app contains
no analytics, advertising, or crash-reporting SDKs.

To provide its VPN functionality, mqvpn transmits network traffic to the VPN
server explicitly configured by the user, as described below.

## VPN traffic

mqvpn connects only to the VPN server that you configure. When the VPN is
active, network traffic selected for the VPN is routed through that server.

Vortric Labs does not receive or process your VPN traffic unless you
explicitly configure a server operated by Vortric Labs. For servers operated
by you or by another party, the handling, logging, retention, and processing
of traffic is determined by that server's operator.

Traffic between the mqvpn app and the configured VPN endpoint is encrypted
using QUIC with TLS 1.3.

## Data stored on your device

Connection settings you enter (server address, port, pre-shared key, tunnel
options) are stored locally on your device only. They leave the device only
as part of connecting to the server you configured.

## Data retention and deletion

Vortric Labs does not retain any personal data because the app does not send
such data to Vortric Labs.

Connection settings are stored locally on your device and remain there until
you change them, clear the app's data, or uninstall the app. Uninstalling the
app or clearing its storage removes these locally stored settings.

## Permissions the app uses

- **VPN service** — required to establish the tunnel. Android shows a system
  consent dialog before the first connection.
- **Network state** — used to detect available networks (Wi-Fi, cellular) for
  multipath bonding and failover.
- **Notifications** — used to show the ongoing connection status.

## Changes

Changes to this policy will be published on this page. Since the app collects
no data, changes are expected only to reflect new app functionality.

## Contact

Questions about this policy: contact@vortric.com or open an issue at
[github.com/mp0rta/mqvpn](https://github.com/mp0rta/mqvpn).
