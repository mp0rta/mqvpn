# ハイブリッドモード（TCP レーン）

ハイブリッドモードは、内側 TCP 接続をクライアント上でローカル終端し（組み込みの [lwIP](https://savannah.nongnu.org/projects/lwip/) スタックを使用）、datagram の CONNECT-IP パスの代わりに専用の HTTP/3 リクエスト**ストリーム**で中継します。

なぜ必要か: 素のマルチパスはフローの datagram を複数パスに分散するため、単一の内側 TCP フローはパス間の並び替わり（reordering）をロスと解釈して送信を絞ってしまいます。TCP ストリームレーンはこの内側 TCP のエンドツーエンド前提を外し、QUIC のストリーム層が順序を復元するため、**単一の TCP フローでも全パスの帯域を集約できます**。ベンチマークでは 2×100 Mbps のボンドで単一 `iperf3` フローが 96 Mbps（raw）から約 187 Mbps（hybrid）に向上しています — [ベンチマーク](../benchmarks/#ハイブリッド-tcp-レーン集約-v0-9-0)を参照してください。

トレードオフは、フローあたりの小さなオーバーヘッド（ローカル TCP 終端 + ストリームフレーミング）と、中継フローの TCP ハンドシェイクに応答するのが最終的な宛先ではなくサーバになる点です。

## パケットの分類

分類はクライアントでパケット単位に行われ、レーンの判定は TCP フローごとに SYN 時点で固定されます:

```
TUN packet
  │
  ▼
classifier (per packet: protocol + Tcp mode + tunnel-subnet carve-out)
  │
  ├─ TCP, Tcp=stream (or Tcp=auto with ≥2 active paths)
  │     └─▶ tcp lane (client-side lwIP) ─▶ HTTP/3 request stream ─▶ server egress connect()
  ├─ UDP (parseable)
  │     └─▶ datagram lane (existing reorder/STAMP path) ─▶ CONNECT-IP DATAGRAM
  └─ everything else (incl. TCP under Tcp=raw, or Tcp=auto with <2 active paths)
        └─▶ raw lane (existing, unchanged) ─▶ CONNECT-IP DATAGRAM
```

デフォルトの `Tcp = auto` では、SYN 時点でアクティブパスが 2 本以上ある場合のみ TCP フローがストリームレーンに乗ります — 単一パスのクライアントはレーンのオーバーヘッドに見合う利得がないため、従来の datagram パスのままです。判定はフローごとに 1 回だけ行われ、再評価されません。

## 有効化

ハイブリッドモードは**デフォルト無効**で、既存のデプロイメントの挙動は変わりません。両側で有効化する必要があります。

### サーバ

```ini
# /etc/mqvpn/server.conf
[Hybrid]
Enabled = true
# EgressAllow = 10.0.5.0/24   # 中継 TCP がプライベートレンジに到達する必要がある場合のみ
```

### クライアント

```ini
# /etc/mqvpn/client.conf
[Hybrid]
Enabled = true
Tcp = auto        # stream | raw | auto（デフォルト）
```

JSON の場合は `"hybrid": {"enabled": true, "tcp": "auto"}` が等価です。全キーのリファレンス（フロー上限、タイムアウト、egress ACL）は[設定 → `[Hybrid]`](./configuration#hybrid)を参照してください。

## サーバ側 egress ACL

中継された TCP はサーバから通常の外向き `connect()` として出ていくため、サーバは**プライベートレンジ宛をデフォルト拒否する egress ACL** を強制します — 何も設定しなくても RFC1918・ループバック・リンクローカル宛は拒否されます。これは、侵害された（または設定を誤った）クライアントが VPN サーバを内部ネットワークへの踏み台として使うことに対する安全側デフォルトです。

中継 TCP が正当にプライベート宛先へ到達する必要がある場合は、明示的に穴を開けます:

```ini
[Hybrid]
Enabled = true
EgressAllow = 10.0.5.0/24
EgressDeny = 10.0.5.13/32   # EgressAllow の後に評価
```

## モニタリング

control API の `get_stats` がレーンのランタイムカウンタをクライアント・サーバ両方で公開します: `tcp_flows_active`、`tcp_flows_total`、`tcp_flows_rejected`、およびレーン別パケットカウンタ（`pkts_lane_*`）。フィールドの意味は [docs/control-api.md §5.4](https://github.com/mp0rta/mqvpn/blob/main/docs/control-api.md) を参照してください。

## iOS ビルド

iOS ビルド（`ios/build-ios.sh`）では、iOS Network Extension のメモリ上限に収めるため、lwIP のフットプリントを削減した構成（`MQVPN_LWIP_IOS_PROFILE` ビルドフラグ: TCP ウィンドウ約 2 MiB / 256 フローに対して約 256 KiB / 64 フロー構成）でレーンをコンパイルします。Android ビルドはデフォルトプロファイルを使用します。このプロファイルは QUIC 側の受信レート上限 [`[Advanced] RecvRateLimit`](./configuration#advanced) とセットで使います — 内側 TCP のウィンドウを縮めるだけでは外側 QUIC コネクション自体のバッファリングは抑えられないため、iOS クライアントは両方を設定します。予算計算と実測値の詳細は
[docs/hybrid_h2_memory_budget.md §5](https://github.com/mp0rta/mqvpn/blob/main/docs/hybrid_h2_memory_budget.md) を参照してください。

## 既知の制限

- **プライベート宛先への TCP には明示的な `EgressAllow` が必要です。** クライアントはサーバの ACL を参照できないため、サーバの egress `connect()` が試行される前に lwIP が内側 SYN にローカルで応答します。ACL による拒否は即時の接続拒否ではなく、後からの RST としてアプリケーションに現れます。
- **`/24` より広いクライアントアドレスプールでは、クライアント間の VPN 内 TCP が拒否されることがあります。** クライアントは自分自身の `/24` のみを TCP レーンから除外します。より広いプールを使う場合はプールをカバーする `EgressAllow` を追加してください（この構成ではサーバが起動時に警告をログします）。
- lwIP が配送できない一部の IPv6 形式（v4-mapped、マルチキャスト、未指定送信元）は TCP レーンではなく raw レーンにルーティングされます。
