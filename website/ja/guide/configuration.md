# 設定

mqvpn は INI と JSON の両方の設定ファイルに対応しています。ファイルの内容が `{` で始まる場合は JSON、それ以外は INI として解析されます。CLI 引数は設定ファイルの値を上書きします。

BOM の有無にかかわらず UTF-8 ファイルと Windows の改行（CRLF）に対応します。
NUL バイトを含むファイルはエラーになります。INI のセクション名とキー名は
大文字・小文字を区別しません。壊れたセクション見出しには警告を出し、
次の有効なセクション見出しまで、その下のキーを無視します。オン・オフを指定するキーには
`true` か `false` を書きます（大文字・小文字は区別しません。JSON では引用符なしの
`true`/`false`）。`on`・`yes`・`1` など、それ以外の値はエラーになり mqvpn は起動しません。

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

[Hybrid]
Enabled = true

[Reorder]
Enabled = true
```

CA が発行した証明書を使う場合、`Cert` (JSON では `cert_file`) にはサーバー証明書と中間証明書を連結した fullchain を指定します。Let's Encrypt では `cert.pem` ではなく `fullchain.pem` です。クライアントはサーバーが送った chain をそのまま検証し、足りない中間証明書を取りに行かないため、leaf だけのファイルでは、その中間証明書を元から信頼していないクライアントで検証に失敗します。

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

# [Hybrid]                      # 内側 TCP を QUIC の stream で運ぶ。詳細は [Hybrid] の節
# Enabled = true

# [Reorder]                     # 内側 QUIC などの大きな転送向け。詳細は [Reorder] の節
# Enabled = true
```

## JSON 形式

JSON は構造化された設定管理や自動化ツールとの連携に便利です。
ファイルは厳密な JSON (RFC 8259) で書きます。コメントや末尾のカンマは使えず、キーと文字列は二重引用符で囲みます。

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
  "cc": "bbr2",
  "hybrid": { "enabled": true },
  "reorder": { "enabled": true }
}
```

`cert_file` にも同じく fullchain を指定します (INI のサーバー例の下の注記を参照)。

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

設定のユーザー名は最大63バイトです。長い名前は切り詰めずに拒否します。
INI では警告を出してそのエントリを無視し、JSON と `--user` ではエラーになります。

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
| `Insecure` | TLS 証明書検証を省略する (自己署名のテスト構成のみ)。`false` ではシステムのストア (`/etc/ssl`。`SSL_CERT_FILE` / `SSL_CERT_DIR` で上書き可) で検証する。Linux/macOS (および custom trust path を使う Windows) では IP アドレス接続時に `ServerName` へ証明書の DNS 名を設定する。Windows の証明書ストアで検証する場合は IP literal が `iPAddress` SAN と直接照合される。Windows では Windows の証明書ストアで検証する。`SSL_CERT_FILE` (PEM バンドル) または `SSL_CERT_DIR` (ハッシュ化した証明書ディレクトリ) が設定されていれば、Linux と同様にそちらを使う。Android では端末の CA ストアとアプリの network security config で検証する。証明書が一致すべき名前は `tlsServerName` (`ServerName` の SDK 版) で、ブラケットなしのホスト名か IP リテラルを指定する。 | `false` |

### `[Interface]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Listen` | リッスンアドレス（サーバーのみ） | `0.0.0.0:443` |
| `Subnet` | クライアント IPv4 プール（サーバーのみ） | `10.0.0.0/24` |
| `Subnet6` | クライアント IPv6 プール（サーバーのみ）。各クライアントには `Subnet` と同じ位置のアドレスが割り当てられるため、同じ数のアドレスを収容できる必要がある（`/24` ならプレフィックス長 `/120` 以下） | — |
| `TunName` | TUN デバイス名 | `mqvpn0` |
| `DNS` | DNS サーバー（カンマ区切り） | — |
| `LogLevel` | ログレベル（`debug`、`info`、`warn`、`error`） | `info` |
| `KillSwitch` | VPN 外への通信を遮断（クライアントのみ）。特定のネットワークアダプタに bind するアプリケーションがトンネルを迂回するのも防ぐ | `false` |
| `Reconnect` | 自動再接続を有効化（クライアントのみ） | `true` |
| `ReconnectInterval` | 再接続の間隔（秒） | `5` |
| `ManageRoutes` | ホストのルーティングテーブルを管理する（VPN ルートとサーバー pin ルート）。自前でルーティングを管理する場合は `false`（または `--no-manage-routes`）を指定。経路の設定だけでは、ソケットを特定のアダプタに bind するアプリケーションは止められない — 下の注記を参照 | `true` |
| `MTU` | TUN MTU（1280–9000）。クライアント: 上限指定 — ネゴシエーション値のほうが小さい場合はそちらが使われる。サーバー: TUN MTU を直接設定。 | auto（クライアント ~1382 ネゴシエーション、サーバー 1382） |
| `PathMTU` | クライアントとサーバー間のネットワークがフラグメントなしで運べる最大の IP パケットサイズ（1280–9000）。mqvpn はこれに収まるように QUIC パケットのサイズを決める。IPv6 ヘッダを前提に計算するので IPv4 でも安全。1500 未満の値は相手にも伝わるため、クライアントの小さい値はサーバーから届くパケットのサイズも制限する。[より大きなトンネル MTU を使う](#using-a-larger-tunnel-mtu) を参照 | `0`（1400 バイトのパケット） |
| `PMTUD` | 固定サイズに頼らず経路 MTU を探索する。パケットは小さいサイズから始まり、より大きなプローブが届く間は大きくしていく。`PathMTU` を設定した場合はそれが上限になる。両端で有効にする必要がある。[経路 MTU の探索](#discovering-the-path-mtu) を参照 | `false` |

> **注記: 経路管理はアダプタに bind するアプリケーションをカバーしない**
>
> mqvpn はシステムのデフォルトルートを置き換えるのではなく、split default ルート（`0.0.0.0/1` + `128.0.0.0/1`）を追加します。元のデフォルトルートはそのまま残るため、宛先への経路ではなく*システムのデフォルトルート*を見てネットワークアダプタを選ぶアプリケーションは、物理アダプタを使い続けてトンネルを迂回します。Windows 版の Tailscale は自身のソケットに対してこの方式を取ります。
>
> これは `ManageRoutes` とは独立した挙動です。こうしたアプリケーションを止めるには `KillSwitch = true` を設定してください。その場合、**トンネル経由になるのではなく遮断される**点に注意してください。

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
| `AllowClientScheduler` | サーバーのみ (JSON では `allow_client_scheduler`、コマンドラインでは `--allow-client-scheduler`)。`true` にすると、スケジューラを指定してきたクライアントには、そのクライアント自身の接続のダウンロード方向でそのスケジューラを使います。ほかのクライアントはサーバーの `Scheduler` のままです。クライアントが `backup_fec` を指定した場合、サーバーの `Scheduler` が `backup_fec` の場合、同じ接続ですでに一度スケジューラを変更した場合、接続がすでに複数のパスを使っている場合は、リクエストは適用されず、その接続は現在のスケジューラ（最初はサーバーの `Scheduler`）のままです。 | `false` |
| `RequestServerScheduler` | クライアントのみ (JSON では `request_server_scheduler`、コマンドラインでは `--request-server-scheduler`)。`true` にすると、このクライアントの `Scheduler` をダウンロード方向にも使うようサーバーに依頼します。`Scheduler` だけを設定した場合は、従来どおりアップロード方向にのみ影響します。`AllowClientScheduler = true` のサーバーでのみ有効です。 | `false` |
| `CC` | 輻輳制御アルゴリズム（`bbr2`, `bbr`, `cubic`, または `none`） | `bbr2` |
| `Path` | バインドするネットワークインターフェース（複数指定可） | デフォルトインターフェース |
| `InitMaxPathId` | 接続を通して使えるパス ID の初期数（番号は 0〜N。パスを作るたびに、作り直しも含めて新しい番号を使う。足りなくなるとサーバーが 128 まで追加する）。`1`–`128`。未設定（`0`）なら `8` | `0` |
| `Reinjection` | 投機的複製モード（`off`, `deadline`, または `idle`）。`dgram` は廃止されました。設定ファイルで指定すると警告が出て `off` で動作します。パケットを複製するには冗長モード（`Redundant = true`）を使ってください。 | `off` |
| `ReinjectionSrttFactorPct` | `deadline` モード: factor × min_srtt を超えた未 ACK パケットを複製、パーセント指定（`100`–`1000`） | `110` |
| `ReinjectionHardDeadlineMs` | `deadline` モード: 複製デッドラインの上限クランプ（`1`–`60000`） | `500` |
| `ReinjectionDeadlineLowerBoundMs` | `deadline` モード: 下限クランプ。上限を超える値は上限に切り詰め（`1`–`60000`） | `20` |
| `Redundant` | クライアント専用。`true` にすると、送信する UDP パケットのコピーを複数の回線で同時に送り、1 本の回線が切れてもライブ配信などが途切れにくくなります。そのトラフィックのデータ使用量は、2 本なら最大 2 倍、3 本なら最大 3 倍です。どの回線もそのトラフィックを単独で運べる速度があることを推奨します。回線が足りないことが多い場合はオフにしてください。[冗長モード](./multipath#冗長モード)を参照してください。 | `false` |
| `RedundantPorts` | クライアント専用。`Redundant = true` のとき複製する宛先ポートをカンマ区切りで指定します（最大 16 個）。空の場合はすべての UDP を複製します。`Redundant = true` のとき、不正な値を指定するとクライアントは起動時に停止します。 | 空 |

このバージョンのサーバーは、`AllowClientScheduler` が `false` の場合でも、接続中の各クライアントに、そのクライアントに対して使っているスケジューラを通知します。`RequestServerScheduler` を設定したクライアントは、接続後に `server scheduler: <name> (requested <name>)` とログに出力します。

スケジューラの詳細は[マルチパス](./multipath)、Reinjection のモード別ガイドは
[マルチパスの Reinjection 節](./multipath)を参照してください。

> `backup_fec` は実験的機能で、両ピアが mqvpn 0.4.0 以降かつ FEC ビルド
> (`-DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON`) を有効にしている必要があります。
> 詳細は[マルチパス](./multipath#backup-fec-experimental)を参照。

> `CC = none`（輻輳制御なし）は xquic を `-DXQC_ENABLE_UNLIMITED=ON` でビルドする必要があります。

### `[Reorder]`

内側 UDP トラフィック向けの、フロー単位の reorder バッファです。mqvpn のマルチパス集約によって複数経路に分散される単一の内側コネクション（例: 内側 QUIC）を対象とし、順序が乱れたデータグラムを短時間だけ保持して順序どおりに配送することで、内側エンドポイントが受け取る順序の乱れを軽減します。デフォルトは無効（`Enabled = false`）で、無効時はこのセクションは効果を持たず、パケットはそのまま転送されます。サーバーとクライアントの両方で `Enabled = true` のときだけ有効になり、そのときクライアントのログに `peer advertised mqvpn-reorder` が出ます。

> **対象範囲:** reorder バッファは **内側 UDP フローのみ** に適用されます。**内側 TCP は reorder バッファでは扱いません。** 内側 TCP は代わりに、後述する hybrid mode（[`[Hybrid]`](#hybrid)）を有効化してください。QUIC stream によって reordering されます。

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Enabled` | マスタースイッチ（`true` / `false`） | `false` |
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

reorder はスループットとレイテンシのトレードオフで、bulk 転送には効きますが、対象になるすべてのフローに遅延を上乗せします。`MaxWaitMs` は欠落データグラムをスキップするまで受信側が待つ時間で、待っている最中に新たに開いたギャップは次の待ちに回されるため、保持時間は名目上 `MaxWaitMs` の 2 倍までです（バッファ上限によるフラッシュで早く解放されることがあり、期限は定期的に確認されるため、少し超過することがあります）。順序どおりに届いたデータグラムは遅延しません。1 本のトンネルは通常その両方のトラフィックを運ぶため、ポート単位の `[ReorderRule]` で、効く所（bulk な内側 QUIC）だけ有効にし、低遅延トラフィック（DNS, NTP, リアルタイム UDP）はパススルーさせられます。マッチしない UDP はデフォルトでパススルーなので、reorder したいポートだけルールを書けば済みます:

```ini
[Reorder]
Enabled = true

[ReorderRule]          # bulk な内側 QUIC: reorder 有効
Proto = udp
Port = 443
Profile = fiber_lte

[ReorderRule]          # DNS: 遅延を絶対に足さない
Proto = udp
Port = 53
Profile = default_udp
```

JSON でも同様に設定できます。`reorder` オブジェクトは上記 INI キーに 1:1 で対応する snake_case キーを使い、`reorder_rules` は `{proto, port, profile}` オブジェクトの配列です（各ルールには任意で `max_wait_ms` / `cap_packets` のオーバーライドを付けられます）:

```json
{
  "reorder": {
    "enabled": true,
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
| `TcpMaxFlows` | 同時 TCP レーンフロー数の上限。**client と server で実装も失敗時の挙動も異なる** — 詳細はこの表の直下の **`TcpMaxFlows`の注意点** を参照 | client + server | `256` |
| `TcpIdleTimeoutSec` | TCP レーンフローのアイドル破棄タイムアウト。`0` で無効化 | client + server | `300` |
| `TcpConnectTimeoutSec` | サーバの egress `connect()` タイムアウト。超過時クライアントは HTTP `504` を受け取ります | server | `10` |
| `TcpMaxGlobalFlows` | 全セッション合計の egress TCP フロー数のサーバ全体上限 | server | `4096` |
| `EgressAllow` | プライベートレンジ向けデフォルト拒否 egress ACL を通す CIDR（繰り返し可、最大 32） | server | — |
| `EgressDeny` | 追加で拒否する CIDR。`EgressAllow` の後に評価されます（繰り返し可、最大 32） | server | — |

#### `TcpMaxFlows`の注意点
`TcpMaxFlows` は client と server で挙動が異なります。
共通しているのはキー名だけで、数える対象も、上限に当たったときの結果も別物になります。

| | client | server |
|---|---|---|
| 数える場所 | レーン自身のフローテーブル | クライアントセッション単位 |
| 判定タイミング | **lwIP が SYN を見る前** | CONNECT-TCP 要求の到着時 |
| 内側 TCP の終端 | lwIP (レーン内) | しない (通常のカーネルソケットで中継) |
| **上限超過時** | **RAW レーンに降格** — 接続は成立する (失敗ではない) | **HTTP `503`** → client はその内側コネクションを **RST**。この時点で RAW 降格はない |
| per-flow メモリ | **~0.75 MiB** (uplink キューの上限) | **~32 KiB** (遅延確保の 16 KiB 中継バッファ × 2) + fd 1 本 |
| 先に尽きる資源 | RAM — worst case は `TcpMaxFlows` × 0.75 MiB (既定 256 で約 192 MiB、4096 で約 3.0 GiB) | **fd 予算** — 全体上限の `TcpMaxGlobalFlows` が先に判定される。ただし RAM も見積もっておくこと: worst case は `TcpMaxGlobalFlows` × 32 KiB (4096 で約 128 MiB、全フローが両方向で一度ずつ pause した場合) |
| 実効値の clamp | lwIP TCP pcb プールの**半分**まで (下記) | なし (lwIP を使わないため) |

**client の clamp:** 実効値は lwIP TCP pcb プールの半分に制限されます。
最大値は、desktop/router ビルド (Linux / Windows / macOS) で `4096`、Android で `256`、
[iOS lwIP プロファイル](./hybrid-mode#ios-ビルド)で `64`になります。

**これは設定値を半分にするものではありません。** 実効値ぶんのフローは同時に張れます。プールの
残り半分は、フローテーブルが数えなくなった pcb (TIME_WAIT / LAST_ACK / CLOSING はフローより
長生きする) が居座るための余白として確保してあります。

JSON では `"hybrid"` オブジェクトに snake_case キーで指定します（`enabled`, `tcp`, `tcp_max_flows`, `tcp_idle_timeout_sec`, `tcp_connect_timeout_sec`, `tcp_max_global_flows`, `egress_allow`, `egress_deny`）。

> egress ACL は `EgressAllow`/`EgressDeny` を何も設定しなくても RFC1918・
> ループバック・リンクローカル宛をデフォルト拒否します。侵害されたクライアントが
> サーバを内部ネットワークへの踏み台に使うことへの安全側デフォルトです。

### `[Advanced]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `RecvRateLimit` | コネクションレベルの受信レート上限（バイト/秒）。QUIC の集約受信ウィンドウを `rate × RTT` に制限します。クライアント側のみ有効 — サーバは無視します（サーバ側で制限するとクライアントのアップロードを絞ってしまうため）。最大値は `10000000000`（10 GB/s）で、それを超える値は警告とともに拒否され `0` にフォールバックします。メモリ制約がある場合を除き `0` のままにしてください（モバイルクライアントは内部で設定します） | `0`（無効） |
| `UdpGso` | 高スループット時に UDP 送信をカーネル GSO でバッチ化し、CPU 使用率を下げます。非対応カーネル（4.18 未満）では通常のバッチ送信に自動的にフォールバックします。Linux / Android のみ有効 — それ以外のプラットフォームでは効果がありません。`false` にすると以前のパケット単位の送信経路に戻ります | `true` |
| `UdpGro` | 高スループット時に受信 UDP パケットをカーネル GRO でまとめて受け取り、CPU 使用率を下げます。非対応カーネル（5.0 未満）では 1 パケットずつの受信に自動的にフォールバックします。Linux のみ有効 — それ以外のプラットフォームでは効果がありません。`false` にすると以前の受信経路に戻ります | `true` |
| `TunOffload` | カーネルがトンネルインターフェースへの通信をまとめて 1 回で渡し、mqvpn 側で分割します。高スループット時の CPU 使用率を下げます。非対応カーネルでは 1 パケットずつの読み取りに自動的にフォールバックします。Linux のみ有効 — それ以外のプラットフォームでは効果がありません。`false` にすると以前のトンネルインターフェースに戻ります | `true` |
| `TunGro` | トンネルインターフェースへ書き込む連続した TCP パケットと、同じサイズの連続した UDP データグラムを 1 回の書き込みにまとめ、高スループット時の CPU 使用率を下げます。UDP データグラムをまとめるのはカーネル 6.2 以降のみで、それより古いカーネルでは従来どおり 1 つずつ書き込みます。`TunOffload` が `false` のときは効果がありません。Linux のみ有効 — それ以外のプラットフォームでは効果がありません。`false` にすると以前のように 1 パケットずつ書き込みます | `true` |

JSON では `"advanced"` オブジェクトに snake_case キーで指定します（`recv_rate_limit`, `udp_gso`, `udp_gro`, `tun_offload`, `tun_gro`）。

## MTU ガイドライン

### デフォルト（auto)

ほとんどの環境では `MTU` を設定する必要はありません。自動ネゴシエーションで決まる値（約 1382）は、標準的な Ethernet（1500）、PPPoE（1492）、モバイル回線でそのまま使えます。

### MTU を明示的に設定すべきケース

| シナリオ | 推奨設定 |
|----------|----------|
| 標準的な Ethernet / モバイル | 設定不要（auto で約 1382） |
| 多段トンネル構成（mqvpn → WG → 別トンネルなど） | 残りの MTU を計算し、1280 に近ければ明示指定 |
| 両端とも 1500 バイトを問題なく通す経路で、より大きなトンネル MTU を使いたい | 両端で `PathMTU = 1500`（TUN MTU 1418） |
| 経路 MTU が不明、または変わる（モバイル、PPPoE、トンネル、ICMP がフィルタされている） | 両端で `PMTUD = true` |

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

### より大きなトンネル MTU を使う {#using-a-larger-tunnel-mtu}

デフォルトの 1400 バイトのパケットサイズは、設定なしで PPPoE やほとんどのモバイル回線に収まります。クライアントとサーバー間のネットワークがより大きなパケットを運べると分かっている場合は、両端で `PathMTU` にそのサイズを設定すると、mqvpn はそれに収まるようにパケットサイズを決めます：

```
PathMTU                    1500 bytes
 − IPv6 + UDP ヘッダ          48 bytes
 − 暗号化タグ                 16 bytes
                           ─────────
 = max_pkt_out_size         1436 bytes（上限）
 − QUIC、DATAGRAM、MASQUE ヘッダ  18 bytes
                           ─────────
 = TUN MTU                  1418 bytes
```

上限サイズのパケットには ACK フレームが載りません。上限未満では ACK フレーム用に 16 バイトの余白も確保するため、`PathMTU = 1492` ではパケットが 1412 バイト、TUN MTU が 1394 になります。QUIC ライブラリがパケットを 1436 バイトで頭打ちにするため、1500 より大きな値を指定しても結果は同じです。`PathMTU` が実際にネットワークが運べるサイズより大きいと、フルサイズのパケットがフラグメントされたり破棄されたりするので、経路が分かっている場合にだけ設定してください。

1500 未満の値は、このエンドが受け取れる最大のパケットとして相手にも伝わり、相手はパケットをその範囲に収めます。そのため `PathMTU = 1500` のサーバー 1 台で、より小さい経路のクライアントにも対応できます。各クライアントが自分の `PathMTU` を設定すると、それに合ったサイズのパケットが届きます。

明示した `MTU` が内側で運べるサイズを超える場合、クライアントは警告して制限します。サーバーも警告しますが、TUN MTU は指定値を維持するため、大きすぎるトンネル内パケットは破棄される場合があります。

トンネル内で IPv6 を使うには、1280 バイトのパケット全体を運べる容量が必要です。IPv6 有効時、0 以外の `PathMTU` は **1378 以上**、reorder 有効時は **1386 以上**が必要です。サーバーは不足する設定での起動を拒否します。クライアントも IPv6 アドレスの割り当て時に送信可能なサイズが不足していれば、エラーを通知して接続を閉じます。`MTU = 1280` を設定しても実際の容量は増えません。IPv4 のみのトンネルでは小さい値を引き続き使用できます。デフォルトの `PathMTU = 0` も引き続き使用できます。

### 経路 MTU の探索 {#discovering-the-path-mtu}

両端で `PMTUD = true` にすると、mqvpn は固定サイズに頼らず、経路が運べるパケットサイズを探索します：

- パケットは、内側 MTU 1280 バイト（IPv6 の最小値）を確保できる最小のサイズから始まります。経路上では IPv4 で 1358 バイト、IPv6 で 1378 バイトで、`[Reorder]` を有効にするとそのヘッダー分の 8 バイトが加わります。
- 経路がそれより小さい場合、mqvpn は QUIC の最小パケットサイズ（1200 バイト）まで下げてそこから探索するので、IPv4 のみのトンネルは TUN MTU 1280 未満で動作し続けます。IPv6 を運ぶトンネルはそうはいかず、クライアントは IPv6 には内側 MTU 1280 が必要というエラーで接続を閉じます。
- より大きなプローブパケットを段階的に送ります。届いたプローブはパケットサイズを引き上げ、失われたプローブは「収まらない」という意味にしかならず、接続を遅くしません。探索は試すサイズごとに数往復かかり、収まる最大サイズの 4 バイト以内で止まります。上限は `PathMTU` を設定していればそのサイズ、なければ 1436 バイト（TUN MTU 1418）です。
- UDP ソケットは Don't Fragment ビットを立てて送信するので、途中でフラグメントされることはありません。探索に ICMP は不要で、ICMP をフィルタするネットワークでも動作します。
- 接続中に経路が小さくなると、大きなパケットは届かなくなり、小さなパケットは届き続けます。mqvpn は現在のサイズで数個のプローブを送って確認し、それも失われた場合は数往復（100 ms の経路で約 1 秒）で開始サイズに戻り、探索をやり直します。古いサイズで送って失われたデータは、収まるパケットで再送されます。
- 探索が上限より下で終わった場合、10 分後に経路が大きくなっていないか、上限から探索し直します。

クライアントの TUN MTU は、探索したサイズに合わせて上下します。サーバーは TUN MTU を変えず、あるクライアントにとって大きすぎるパケットには、そのクライアントのサイズを載せた ICMP Packet Too Big を返します。

マルチパスでは各パスを探索し、接続は最も小さいパスのサイズを使います。後から追加されたパスは開始サイズから始まるため、そのパスの探索が済むまで接続は開始サイズに戻ります。検証中のパスは数に入らないため、通らないパスがあっても接続のサイズは下がりません。

PMTUD は Linux・macOS・Windows のクライアントと Linux のサーバーで動作します。Android SDK では `MqvpnConfig` に `pmtud = true`（上限には `pathMtu`）を設定します。Android は TUN MTU をトンネル確立時にしか設定できないため、1280 のままです。経路が小さくなってもトンネルは動作し続けますが、アップロードは探索した大きなサイズを使いません。

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
systemd ユニットは上記の `.conf` パスを使います。内容は INI・JSON のどちらでも
指定でき、サーバーの NAT ヘルパーは起動時に mqvpn 本体と同じ設定パーサを使います。
停止時は設定ファイルが変更・削除されていても、追加したファイアウォールルールを
削除し、保存済みの転送設定を復元します。
手動でインストールする場合は、`mqvpn-server-nat.sh` と `mqvpn-nat-config` を
インストール先の `lib/mqvpn` ディレクトリに一緒に配置してください。
:::
