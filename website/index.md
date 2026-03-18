---
layout: home

hero:
  name: mqvpn
  text: Multipath QUIC VPN
  tagline: Seamless failover and bandwidth aggregation built on MASQUE CONNECT-IP (RFC 9484)
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: View on GitHub
      link: https://github.com/mp0rta/mqvpn

features:
  - icon: 🔀
    title: Multipath
    details: Bind multiple interfaces (WiFi + LTE, dual ISP). Seamless failover with zero downtime and bandwidth aggregation via the WLB scheduler.
  - icon: ⚙️
    title: Sans-I/O Architecture
    details: Platform-agnostic C library with no I/O dependencies. The tick()-driven model makes it easy to port to any platform.
  - icon: 🖥️
    title: Cross-Platform
    details: Linux today, with Windows and Android support in progress. The sans-I/O design enables new platforms with minimal effort.
  - icon: 📐
    title: Standards-Based
    details: Built on MASQUE CONNECT-IP (RFC 9484), HTTP Datagrams (RFC 9297), QUIC Datagrams (RFC 9221), and Multipath QUIC.
---
