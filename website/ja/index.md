---
layout: home

hero:
  name: mqvpn
  text: マルチパス QUIC VPN
  tagline: MASQUE CONNECT-IP (RFC 9484) によるシームレスなフェイルオーバーと帯域集約
  actions:
    - theme: brand
      text: はじめる
      link: /ja/guide/getting-started
    - theme: alt
      text: GitHub で見る
      link: https://github.com/mp0rta/mqvpn

features:
  - icon: 🔀
    title: マルチパス
    details: 複数インターフェース（WiFi + LTE、デュアルISP）をバインド。WLBスケジューラによるゼロダウンタイムのフェイルオーバーと帯域集約。
  - icon: ⚙️
    title: Sans-I/O アーキテクチャ
    details: I/O依存のないプラットフォーム非依存のCライブラリ。tick()駆動モデルにより、あらゆるプラットフォームへの移植が容易。
  - icon: 🖥️
    title: クロスプラットフォーム
    details: 現在Linux対応。Windows・Androidサポートは開発中。Sans-I/O設計により最小限の労力で新プラットフォームに対応可能。
  - icon: 📐
    title: 標準準拠
    details: MASQUE CONNECT-IP (RFC 9484)、HTTP Datagrams (RFC 9297)、QUIC Datagrams (RFC 9221)、Multipath QUIC上に構築。
---
