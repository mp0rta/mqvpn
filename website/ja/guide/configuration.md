# 設定

mqvpn は INI と JSON の両方の設定ファイルに対応しています。ファイルの内容が `{` で始まる場合は JSON、それ以外は INI として解析されます。CLI 引数は設定ファイルの値を上書きします。

## INI 形式

### サーバー

```ini
# /etc/mqvpn/server.conf
[Interface]
Listen = 0.0.0.0:443
Subnet = 10.0.0.0/24
Subnet6 = 2001:db8:1::/112
# MTU = 1280

[TLS]
Cert = /etc/mqvpn/server.crt
Key = /etc/mqvpn/server.key

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=
User = alice:<ALICE_PSK>
User = bob:<BOB_PSK>

[Multipath]
Scheduler = wlb
# CC = bbr2                     # Congestion control (bbr2|bbr|cubic|none)
```

### クライアント

```ini
# /etc/mqvpn/client.conf
[Server]
Address = 203.0.113.1:443
# ServerName = vpn.example.com  # TLS SNI / 証明書検証名（デフォルト: Address のホスト部）

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Interface]
TunName = mqvpn0
DNS = 1.1.1.1, 8.8.8.8
LogLevel = info
# MTU = 1280

[Multipath]
Scheduler = wlb
# CC = bbr2                     # Congestion control (bbr2|bbr|cubic|none)
Path = eth0
Path = wlan0
```

## JSON 形式

JSON は構造化された設定管理や自動化ツールとの連携に便利です。

### サーバー

```json
{
  "mode": "server",
  "listen": "0.0.0.0:443",
  "tun_name": "mqvpn0",
  "log_level": "info",
  "subnet": "10.0.0.0/24",
  "subnet6": "2001:db8:1::/112",
  "cert_file": "/etc/mqvpn/server.crt",
  "key_file": "/etc/mqvpn/server.key",
  "auth_key": "<YOUR_PSK_HERE>",
  "users": [
    { "name": "alice", "key": "<ALICE_PSK>" },
    { "name": "bob", "key": "<BOB_PSK>" }
  ],
  "max_clients": 64,
  "scheduler": "wlb",
  "cc": "bbr2"
}
```

### クライアント

```json
{
  "mode": "client",
  "server_addr": "203.0.113.1:443",
  "tls_server_name": "vpn.example.com",
  "tun_name": "mqvpn0",
  "log_level": "info",
  "auth_key": "<YOUR_PSK_HERE>",
  "insecure": false,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "kill_switch": false,
  "reconnect": true,
  "reconnect_interval": 5,
  "scheduler": "wlb",
  "cc": "bbr2",
  "paths": ["eth0", "wlan0"]
}
```

## マルチユーザー認証

サーバーでは複数のユーザーをそれぞれ個別の PSK で認証できます。JSON config では `users` 配列で設定します。各要素はオブジェクト形式（`{"name":"alice","key":"..."}`）または省略形の文字列（`"alice:key"`）のどちらでも指定可能です。INI config では `[Auth]` セクションに `User = NAME:KEY` 行を複数書きます。[Control API](#control-api) を使って実行中にユーザーを管理することもできます。

`auth_key`（グローバルキー）と `users` を両方設定した場合、クライアントはどちらでも認証可能です。名前付きユーザーのみに制限するには、`auth_key` を設定から削除してください。

Control API でユーザーを削除すると、そのユーザー名で認証された接続中のセッションも切断されます。

::: warning 監視は per-user 鍵が必須
複数クライアントで `auth_key`（グローバル鍵）を共有しても VPN データプレーンは動作しますが、Control API と Prometheus exporter は `user` ラベルでクライアントを識別します。グローバル鍵で認証したセッションは `user="(global)"` として報告されるため、複数クライアントが同一ラベルに衝突して Prometheus のスクレイプ全体が破棄されます。複数クライアントを監視する場合は、各クライアントに `users` で個別エントリを作成するか、`add_user` で実行時に登録してください。
:::

## 設定ファイルでの実行

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/server.json
```

## 設定リファレンス

### `[Server]`（クライアントのみ）

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Address` | サーバーアドレス（`HOST:PORT`、IPv6 は `[2001:db8::1]:443` 形式） | 必須 |
| `ServerName` | TLS SNI および証明書検証名。IP 直接接続でドメイン証明書を検証する場合に使用 | Address のホスト部 |
| `Insecure` | TLS 証明書検証をスキップ | `false` |

### `[Interface]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Listen` | リッスンアドレス（サーバーのみ） | `0.0.0.0:443` |
| `Subnet` | クライアント IPv4 プール（サーバーのみ） | `10.0.0.0/24` |
| `Subnet6` | クライアント IPv6 プール（サーバーのみ） | — |
| `TunName` | TUN デバイス名 | `mqvpn0` |
| `DNS` | DNS サーバー（カンマ区切り） | — |
| `LogLevel` | ログレベル（`debug`、`info`、`warn`、`error`） | `info` |
| `KillSwitch` | VPN 外への通信を遮断（クライアントのみ） | `false` |
| `Reconnect` | 自動再接続を有効化（クライアントのみ） | `true` |
| `ReconnectInterval` | 再接続の間隔（秒） | `5` |
| `ManageRoutes` | ホストのルーティングテーブルを管理する（VPN ルートとサーバー pin ルート）。自前でルーティングを管理する場合は `false`（または `--no-manage-routes`）を指定 | `true` |
| `MTU` | TUN MTU（1280–9000）。クライアント: 上限指定 — ネゴシエーション値のほうが小さい場合はそちらが使われる。サーバー: TUN MTU を直接設定。 | auto（クライアント ~1382 ネゴシエーション、サーバー 1382） |

### `[TLS]`（サーバーのみ）

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Cert` | TLS 証明書パス（PEM） | 必須 |
| `Key` | TLS 秘密鍵パス（PEM） | 必須 |

### `[Auth]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Key` | 事前共有鍵（base64、`mqvpn --genkey` で生成） | `User` 未設定時は必須 |
| `User` | ユーザー個別の PSK（`NAME:KEY` 形式、複数指定可） | — |
| `MaxClients` | 最大同時接続クライアント数（サーバーのみ） | `64` |

JSON ではクライアント・サーバーとも `auth_key` を使います（上の例のとおり）。

### `[Multipath]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Scheduler` | スケジューラアルゴリズム（`minrtt`, `wlb`, `wlb_udp_pin`, または `backup_fec`） | `wlb` |
| `CC` | 輻輳制御アルゴリズム（`bbr2`, `bbr`, `cubic`, または `none`） | `bbr2` |
| `Path` | バインドするネットワークインターフェース（複数指定可） | デフォルトインターフェース |
| `InitMaxPathId` | MP-QUIC draft-21 テスト用ノブ: transport parameters で広告する初期 Maximum Path Identifier（`1`–`4294967295`、`0` = xquic デフォルト `8`） | `0` |

スケジューラの詳細は[マルチパス](./multipath)を参照してください。

> `backup_fec` は実験的機能で、両ピアが mqvpn 0.4.0 以降かつ FEC ビルド
> (`-DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON`) を有効にしている必要があります。
> 詳細は[マルチパス](./multipath#backup-fec-experimental)を参照。

> `CC = none`（輻輳制御なし）は xquic を `-DXQC_ENABLE_UNLIMITED=ON` でビルドする必要があります。

### `[Reorder]`

内側 UDP トラフィック向けの、フロー単位の reorder バッファです。mqvpn のマルチパス集約によって複数経路に分散される単一の内側コネクション（例: 内側 QUIC）を対象とし、順序が乱れたデータグラムを短時間だけ保持して順序どおりに配送することで、内側エンドポイントが受け取る順序の乱れを軽減します。デフォルトは無効（`Enabled = off`）で、無効時はこのセクションは効果を持たず、パケットはそのまま転送されます。

> **対象範囲:** reorder バッファは現在 **内側 UDP フローのみ** に適用されます。**内側 TCP はまだ reorder バッファでは扱いません（TODO）。** 内側 TCP は代わりに、TCP フローを単一経路に固定するスケジューラのフローピン留め（`wlb` / `wlb_udp_pin`）と、TCP 自身の順序乱れ耐性（RACK/SACK）に依存します。

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Enabled` | マスタースイッチ（`on` / `off`） | `off` |
| `MaxWaitMs` | 欠落データグラムをスキップするまで、ギャップを保持する時間（ms） | `30` |
| `CapPackets` | フローあたりの最大バッファデータグラム数（2 のべき乗） | `1024` |
| `MaxBytesPerFlow` | フローあたりの最大バッファバイト数 | `1572864` |
| `ClassifyWindow` | フローの方向を判定するために観測するデータグラム数（`0` で ACK 方向のデモートを無効化） | `64` |
| `AckDemoteMaxLarge` | この値以下の大パケット数であればフローを ACK 方向と判定する | `3` |
| `SmallPacketThreshold` | small / large を分ける内側ペイロードのバイト数 | `200` |
| `ResetMarkPackets` | フロー再開時に送出する FLOW_RESET マーク数 | `8` |
| `ResetIdleGraceMs` | フローがこの時間以上アイドルだった場合のみ FLOW_RESET を尊重する（ms） | `10000` |
| `MaxFlows` | 追跡する最大フロー数 | `65536` |
| `GlobalMaxBytes` | 全フロー共有のバッファバイト予算 | `67108864` |
| `IngressIdleSec` | 受信側のアイドル退避タイムアウト（`EgressIdleSec` より小さい必要あり） | `30` |
| `EgressIdleSec` | 送信側のアイドル退避タイムアウト | `300` |

ACK 方向のデモートは自動です。ACK / 制御ストリームのように見える（ほとんどが小さいパケットの）フローはパススルーへ移され、遅延されることがなくなります。これは内部的な挙動であり設定可能なつまみではありません — `ClassifyWindow` / `AckDemoteMaxLarge` / `SmallPacketThreshold` を通じて間接的に調整します。

reorder はスループットとレイテンシのトレードオフで、bulk 転送には効きますが、対象になるすべてのフローに最大 `MaxWaitMs` の遅延を上乗せします。1 本のトンネルは通常その両方のトラフィックを運ぶため、ポート単位の `[ReorderRule]` で、効く所（bulk な内側 QUIC）だけ有効にし、低遅延トラフィック（DNS, NTP, リアルタイム UDP）はパススルーさせられます。マッチしない UDP はデフォルトでパススルーなので、reorder したいポートだけルールを書けば済みます:

```ini
[Reorder]
Enabled = on

[ReorderRule]          # bulk な内側 QUIC: reorder 有効
Proto = udp
Port = 443
Profile = fiber_lte

[ReorderRule]          # DNS: 遅延を絶対に足さない
Proto = udp
Port = 53
Profile = default_udp
```

…または JSON でも同様に設定できます。`reorder` オブジェクトは上記 INI キーに 1:1 で対応する snake_case キーを使い、`reorder_rules` は `{proto, port, profile}` オブジェクトの配列です（各ルールには任意で `max_wait_ms` / `cap_packets` のオーバーライドを付けられます）:

```json
{
  "reorder": {
    "enabled": "on",
    "max_wait_ms": 30,
    "cap_packets": 1024,
    "max_bytes_per_flow": 1572864,
    "classify_window": 64,
    "ack_demote_max_large": 3,
    "small_packet_threshold": 200,
    "reset_mark_packets": 8,
    "reset_idle_grace_ms": 10000,
    "max_flows": 65536,
    "global_max_bytes": 67108864,
    "ingress_idle_sec": 30,
    "egress_idle_sec": 300
  },
  "reorder_rules": [
    { "proto": "udp", "port": 443, "profile": "cellular_bond" },
    { "proto": "udp", "port": 4500, "profile": "fiber_lte", "max_wait_ms": 50, "cap_packets": 2048 }
  ]
}
```

### プロファイルプリセット

各プロファイルは、実測でチューニングした `(MaxWaitMs, CapPackets)` のプリセットを持ちます。これらの値は 16 種類のリンク環境にわたる `netem` マルチパス実測スイープから選定したもので、手法と環境別データの詳細は[reorder-only マルチパス実測レポート](https://github.com/mp0rta/mqvpn/blob/main/docs/report/2026-06-18-reorder-only-datagram-multipath-connect-ip-en.md)にあります:

| プロファイル | `MaxWaitMs` | `CapPackets` | 備考 |
|--------------|------------:|-------------:|------|
| `cellular_bond` | `50` | `1024` | セルラーボンディング（例: デュアル LTE） |
| `fiber_lte` | `50` | `2048` | 光 + LTE の混在。BDP が大きいため cap を拡大 |
| `quic_bulk` | `50` | `1024` | `cellular_bond` の後方互換エイリアス |
| `low_latency` | — | — | 予約済み。プリセットなし（無効） |
| `default_udp` | — | — | マッチするが reorder **しない**（パススルー / OFF） |

ルールの実効 `(MaxWaitMs, CapPackets)` の**優先順位**（高い順）:

1. ルール自身に明示された `MaxWaitMs` / `CapPackets` キー。
2. グローバルな `[Reorder]` に明示された `MaxWaitMs` / `CapPackets`。
3. ルールのプロファイルプリセット（上表）。
4. ビルトインのデフォルト（`MaxWaitMs = 30`、`CapPackets = 1024`）。

つまり、数値が明示されていれば常にプロファイルより優先されます。グローバルな `[Reorder] MaxWaitMs` を `Profile = quic_bulk` と併用している設定が、明示したグローバル値をそのまま使い続けるのはこのためです。

### reorder を有効にすべきとき

reorder は**デフォルトで無効**であり、有効な範囲の中でのみ opt-in で使うことを想定しています。実測では、その範囲はおおむね RTT のばらつきが **15〜100 ms**、ジッタのある経路、または**帯域が非対称**なケースです。

- **帯域の非対称が強い場合（おおむね 8:1 以上）:** `MaxWaitMs` を `150`〜`200` まで上げることを検討してください（未検証 — 実回線での検証を要するフォローアップとして扱ってください）。
- **RTT のばらつきが極端な場合（285 ms 以上、静止衛星クラス）:** ここでは reorder はかえって性能を下げます。その種のトラフィックでは `Profile = default_udp` で無効のままにしてください。

### `[ReorderRule]`（繰り返し可）

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Proto` | マッチする L4 プロトコル（`udp`） | `udp` |
| `Port` | マッチするポート（送信元または宛先） | — |
| `Profile` | `cellular_bond`, `fiber_lte`, `quic_bulk`, `low_latency`, または `default_udp` | `quic_bulk` |
| `MaxWaitMs` | このルールのみの保持時間（ms）のオーバーライド。`0` は警告付きで拒否されます — ポートを素通しさせたい場合は代わりに `Profile = default_udp` を使ってください | プロファイルプリセット |
| `CapPackets` | このルールのみのフローあたりバッファ上限のオーバーライド。0 以外の 2 のべき乗である必要があり、そうでなければ警告付きで拒否されます | プロファイルプリセット |

### `[Hybrid]`

内側 TCP をクライアントでローカル終端し、HTTP/3 リクエストストリームで中継することで、単一の TCP フローでも複数パスの帯域を集約できるようにします。デフォルト無効。レーン図・egress ACL の意味論・既知の制限は[ハイブリッドモード](./hybrid-mode)を参照してください。

| キー | 説明 | 対象 | デフォルト |
|------|------|------|-----------|
| `Enabled` | マスタースイッチ | client + server | `false` |
| `Tcp` | フロー単位の TCP レーンポリシー: `stream`（常に使用）、`raw`（不使用 — hybrid 無効時とバイト同一）、`auto`（SYN 時点でアクティブパスが 2 本以上なら TCP レーン。判定はフローの生存期間中固定） | client | `auto` |
| `TcpMaxFlows` | 同時 TCP レーンフロー数の上限。client: ローカルフローテーブル（超過 SYN は RAW にフォールバック）。server: クライアントセッション単位（超過 SYN は HTTP `503`）。これは**本数**の上限だが、TCP レーンのメモリを縛るのもこの値。レーン所有の per-flow uplink キューには ~2.25 MiB という上限があるため、client 側の worst case は `TcpMaxFlows` × 2.25 MiB（既定の 256 で約 576 MiB、4096 で約 9.0 GiB）。搭載 RAM から逆算して決める。cap 超過の SYN は失敗ではなく RAW レーンに降格する。client 側ではさらに lwIP TCP pcb プールの半分に clamp される。上限はビルドプロファイルごとに異なり、desktop/router ビルド（Linux / Windows / macOS）で `4096`、Android で `256`、[iOS lwIP プロファイル](./hybrid-mode#ios-ビルド)で `64` — clamp 時はログに出力。プールの残り半分はフローテーブルが数えなくなった TIME_WAIT / LAST_ACK / CLOSING の pcb 用。この余裕がないと lwIP は pcb プールを枯渇させ、新規受け入れのために**確立済みの**内側コネクションを kill し始める（レーン側の cap が先に SYN を断る、という設計が崩れる）ため | client + server | `256` |
| `TcpIdleTimeoutSec` | TCP レーンフローのアイドル破棄タイムアウト。`0` で無効化 | client + server | `300` |
| `TcpConnectTimeoutSec` | サーバの egress `connect()` タイムアウト。超過時クライアントは HTTP `504` を受け取ります | server | `10` |
| `TcpMaxGlobalFlows` | 全セッション合計の egress TCP フロー数のサーバ全体上限 | server | `4096` |
| `EgressAllow` | プライベートレンジ向けデフォルト拒否 egress ACL を通す CIDR（繰り返し可、最大 32） | server | — |
| `EgressDeny` | 追加で拒否する CIDR。`EgressAllow` の後に評価されます（繰り返し可、最大 32） | server | — |

JSON では `"hybrid"` オブジェクトに snake_case キーで指定します（`enabled`, `tcp`, `tcp_max_flows`, `tcp_idle_timeout_sec`, `tcp_connect_timeout_sec`, `tcp_max_global_flows`, `egress_allow`, `egress_deny`）。

> egress ACL は `EgressAllow`/`EgressDeny` を何も設定しなくても RFC1918・
> ループバック・リンクローカル宛をデフォルト拒否します。侵害されたクライアントが
> サーバを内部ネットワークへの踏み台に使うことへの安全側デフォルトです。

### `[Advanced]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `RecvRateLimit` | コネクションレベルの受信レート上限（バイト/秒）。QUIC の集約受信ウィンドウを `rate × RTT` に制限します。クライアント側のみ有効 — サーバは無視します（サーバ側で制限するとクライアントのアップロードを絞ってしまうため）。最大値は `10000000000`（10 GB/s）で、それを超える値は警告とともに拒否され `0` にフォールバックします。メモリ制約がある場合を除き `0` のままにしてください（モバイルクライアントは内部で設定します） | `0`（無効） |

JSON では `"advanced"` オブジェクトに snake_case キーで指定します（`recv_rate_limit`）。

## MTU ガイドライン

### デフォルト（auto）— 通常はそのままで OK

ほとんどの環境では `MTU` を設定する必要はありません。自動ネゴシエーションで決まる値（約 1382）は、標準的な Ethernet（1500）、PPPoE（1492）、モバイル回線でそのまま使えます。

### MTU を明示的に設定すべきケース

| シナリオ | 推奨設定 |
|----------|----------|
| 標準的な Ethernet / モバイル | 設定不要（auto で約 1382） |
| 多段トンネル構成（mqvpn → WG → 別トンネルなど） | 残りの MTU を計算し、1280 に近ければ明示指定 |

クライアントでは、`MTU` を設定すると `min(設定値, ネゴシエーション値)` が実際の TUN MTU になり、設定値がネゴシエーション値を超えている場合は warning ログが出力されます。サーバーでは、`MTU` は TUN MTU をそのまま設定します（デフォルト 1382）。

::: tip
クライアントで `MTU` にネゴシエーション値（約 1382）より大きい値を指定しても効果はありません。ネゴシエーション値が常に上限になります。サーバーでは設定値がそのまま TUN デバイスに適用され、各クライアントのネゴシエーション MSS を超えるパケットには ICMP Packet Too Big を送信元へ返し、送信元側でパケットサイズを調整させます（Path MTU Discovery）。
:::

### TUN MTU の算出方法

mqvpn は接続確立時に、QUIC DATAGRAM の Maximum Segment Size（MSS）をもとに TUN MTU を算出します。`max_pkt_out_size` がデフォルトの 1400 の場合、オーバーヘッドの内訳は以下のとおりです：

```
max_pkt_out_size           1400 bytes
 − QUIC short header         13 bytes
 − DATAGRAM frame header      3 bytes
 − MASQUE datagram header      2 bytes
                           ─────────
 = TUN MTU                  1382 bytes
```

このネゴシエーションは**クライアント**側で接続確立時に行われ、クライアントの TUN MTU はそれに追従します。**サーバー**は起動時に TUN MTU を一度だけ設定します（デフォルト 1382、または設定値）。ネゴシエーション MSS が 1382 より小さいクライアント宛の超過パケットは、サーバーがそのクライアントの MSS を MTU 値として ICMP Packet Too Big を送信元へ返します。送信元はこれを受けてパケットサイズを下げるため（Path MTU Discovery）、サーバーの TUN MTU を全クライアント共通で縮める必要はありません。

### mqvpn トンネル内で別のトンネルを使う場合

mqvpn の上にさらに WireGuard や IPsec、GRE などを重ねると、その分だけ有効 MTU が小さくなります。内側プロトコルの最低 MTU 要件を満たしているか確認してください。

**例：mqvpn の上で WireGuard を使う**

```
mqvpn TUN MTU                    1382 bytes
 − WireGuard オーバーヘッド（IPv6）  80 bytes
                                 ─────────
 = WireGuard 内側 MTU            1302 bytes
   → IPv6 最小 MTU（1280）          ✓
   → QUIC/HTTP3 UDP ペイロード    1254 bytes > 1200  ✓
```

### 制約一覧

| 制約 | 値 | 根拠 |
|------|-----|------|
| config 下限 | 1280 | IPv6 最小 MTU（RFC 8200） |
| config 上限 | 9000 | ジャンボフレーム MTU |
| QUIC 最小 UDP ペイロード | 1200 | RFC 9000 §14（ハンドシェイク要件） |
| auto の値 | ~1382（クライアント: ネゴシエーション、サーバー: 固定デフォルト） | `max_pkt_out_size`（1400）から導出 |

## Control API

稼働中のサーバーに対して、ローカル TCP ソケット経由で JSON コマンドを送ることで、再起動なしにユーザーの追加・削除などの管理操作が行えます。

### 有効化

```bash
sudo mqvpn --mode server ... --control-port 9090
```

デフォルトでは `127.0.0.1` にバインドされます。認証機能はないため、信頼できるインターフェースのみにバインドしてください。

### 設定ファイルから有効化する

Control API は `/etc/mqvpn/server.conf` からも有効化できます：

```ini
[Control]
Listen = 127.0.0.1:9090
```

JSON 設定の場合：

```json
{
  "control_listen": "127.0.0.1:9090"
}
```

CLI フラグ（`--control-port`, `--control-addr`）は設定ファイルの値を**フィールド単位**で上書きします。`--control-port 0` を指定すると、`[Control] Listen` が設定ファイルに書かれていても明示的に無効化できます。

### コマンド

ユーザーの追加：

```bash
echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' | nc 127.0.0.1 9090
```

ユーザーの削除：

```bash
echo '{"cmd":"remove_user","name":"carol"}' | nc 127.0.0.1 9090
```

ユーザーを削除すると、そのユーザー名で認証された接続中のセッションも切断されます。

ユーザー一覧の取得：

```bash
echo '{"cmd":"list_users"}' | nc 127.0.0.1 9090
```

統計情報の取得：

```bash
echo '{"cmd":"get_stats"}' | nc 127.0.0.1 9090
```

詳細なステータスの取得（クライアント・パス単位）：

```bash
echo '{"cmd":"get_status"}' | nc 127.0.0.1 9090
```

整形された出力には組み込みの status コマンドも使えます：

```bash
mqvpn --status --control-port 9090
```

すべてのコマンドは `"ok"` フィールドを含む JSON レスポンスを返します。各接続は 1 コマンドを処理するとサーバー側で切断されるため、コマンドごとに新しい接続を開いてください。

## systemd

deb パッケージや install.sh でインストール済みの場合、systemd ユニットは自動的に配置されます。ソースからビルドした場合は手動でインストールします：

```bash
sudo cmake --install build --prefix /usr/local
```

### サーバー

install.sh を使った場合は `/etc/mqvpn/server.conf` が自動生成されています。手動で設定する場合はサンプルをコピーします：

```bash
sudo cp /etc/mqvpn/server.conf.example /etc/mqvpn/server.conf
sudo vi /etc/mqvpn/server.conf   # 証明書パス、認証キーなどを編集
sudo systemctl enable --now mqvpn-server
```

### クライアント（テンプレートユニット）

クライアントはテンプレートユニットを使用します。インスタンス名が設定ファイル名に対応します：

```bash
sudo cp /etc/mqvpn/client.conf.example /etc/mqvpn/client-home.conf
sudo vi /etc/mqvpn/client-home.conf   # サーバーアドレス、認証キーなどを編集
sudo systemctl enable --now mqvpn-client@home
# → /etc/mqvpn/client-home.conf を読み込みます
```

::: info
systemd ユニットは INI 形式の `.conf` ファイルを前提としています。サーバーユニットの NAT ヘルパースクリプトも INI を直接パースするため、標準ユニットのままでは JSON は使用できません。
:::
