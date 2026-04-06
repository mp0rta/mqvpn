# アーキテクチャ

mqvpn は **[sans-I/O](https://sans-io.readthedocs.io/) C ライブラリ**（`libmqvpn`）として構築されており、その上にプラットフォーム固有のレイヤーを重ねる設計です。VPN プロトコルエンジンとすべての I/O 操作を分離することで、あらゆるプラットフォームへの移植を可能にしています。

## Sans-I/O 設計

ライブラリはプラットフォーム固有のイベントループやデバイス管理を内包せず、`tick()` と入力注入 API で駆動されます。受信した UDP データや TUN パケットは `on_socket_recv()` / `on_tun_packet()` で注入され、送信は xquic の送信コールバック経由で UDP ソケットに書き込まれます（CLI は fd-only モード）。

```
┌──────────────────────────────────────────────┐
│  Platform Layer (owns I/O)                   │
│  ┌──────────┐ ┌───────────┐ ┌───────────┐    │
│  │ Linux CLI│ │ Android   │ │ Windows   │    │
│  │(libevent)│ │ (Handler) │ │ (IOCP)    │    │
│  └────┬─────┘ └─────┬─────┘ └─────┬─────┘    │
│       │ tick()      │ tick()      │ tick()   │
├───────┴─────────────┴─────────────┴──────────┤
│  libmqvpn (core engine — no I/O)             │
│  ┌────────────────────────────────────────┐  │
│  │ mqvpn_client.c / mqvpn_server.c        │  │
│  │ mqvpn_config.c / auth.c                │  │
│  │ path_mgr.c / flow_sched.c / addr_pool  │  │
│  └────────────────────────────────────────┘  │
│       │ xquic callbacks                      │
├───────┴──────────────────────────────────────┤
│  xquic (QUIC / HTTP/3 / MASQUE engine)       │
│  BoringSSL (TLS 1.3)                         │
└──────────────────────────────────────────────┘
```

### なぜ Sans-I/O か？

- **移植性** — 各プラットフォームが独自のイベントループ（libevent、Android Handler、GCD、IOCP）を提供します。ライブラリはスレッドモデルを強制しません。
- **テスト容易性** — `tick()` 関数が状態遷移を同期的に駆動するため、ユニットテストがタイミング問題なく決定的に実行できます。
- **省電力** — プラットフォームが CPU のウェイクアップタイミングを制御します。ライブラリは `interest.is_idle` でアイドル状態を報告します。
- **依存の分離** — ライブラリ自体はイベントループ実装を持たず、プラットフォーム層が libevent や OS 依存ライブラリ（Linux では pthread など）を扱います。

これは [WireGuard (BoringTun)](https://github.com/cloudflare/boringtun) や [msquic](https://github.com/microsoft/msquic) が採用しているのと同じパターンです。

## データフロー

プラットフォーム層はシンプルなループでライブラリを駆動します：

```c
// 1. Config とクライアントの作成
cfg = mqvpn_config_new();
mqvpn_config_set_server(cfg, "1.2.3.4", 443);
mqvpn_config_set_auth_key(cfg, "base64...");
client = mqvpn_client_new(cfg, &callbacks, user_ctx);

// 2. ネットワークパス（UDP ソケット）の追加
mqvpn_client_add_path_fd(client, udp_fd, &desc);

// 3. 接続してエンジンを駆動
mqvpn_client_connect(client);

while (running) {
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(client, &interest);
    int next_ms = interest.next_timer_ms;

    poll(fds, nfds, next_ms);

    // 受信した UDP データを注入
    if (udp_readable)
        mqvpn_client_on_socket_recv(client, path, buf, len, &peer, peerlen);

    // TUN パケットを注入
    if (tun_readable)
        mqvpn_client_on_tun_packet(client, pkt, len);

    // エンジンを駆動 — キューされた処理を実行し、コールバックを呼び出し
    mqvpn_client_tick(client);
}
```

## コールバックモデル

ライブラリはコールバックを通じてプラットフォームに通知します：

| コールバック | タイミング | プラットフォームの対応 |
|-------------|-----------|---------------------|
| `tun_output` | 復号されたパケットが準備完了 | TUN デバイスに書き込み |
| `send_packet` | ops パス利用時に送信要求 | プラットフォーム側送信関数で UDP 送信 |
| `tunnel_config_ready` | サーバーが IP/MTU を割り当て | TUN デバイスを作成・設定 |
| `state_changed` | 接続状態の遷移 | UI 更新、再接続処理 |
| `path_event` | パス状態の変化 | ログ記録、ルーティング調整 |
| `log` | ログメッセージ | ログに書き込み |

現行 CLI 実装は fd-only モードのため `send_packet` は使わず、xquic の送信コールバックからソケット送信を行います。

すべてのコールバックは `tick()` を呼び出したスレッドと同じスレッドで呼び出されます — 同期処理は不要です。

## コンポーネント

| コンポーネント | ファイル | 役割 |
|--------------|---------|------|
| クライアントエンジン | `mqvpn_client.c` | QUIC 接続、MASQUE CONNECT-IP、ステートマシン |
| サーバーエンジン | `mqvpn_server.c` | マルチクライアント処理、アドレス割り当て |
| Config ビルダー | `mqvpn_config.c` | Opaque な設定構造、setter 関数、ABI 互換性 |
| パスマネージャ | `path_mgr.c` | UDP パスのライフサイクル管理、追加/削除/プローブ |
| フロースケジューラ | `flow_sched.c` | WLB および MinRTT パケットスケジューリング |
| アドレスプール | `addr_pool.c` | サーバー側 IP アドレス割り当て |
| 認証 | `auth.c` | TLS 1.3 上の PSK 認証 |

## プラットフォーム移植

mqvpn を新しいプラットフォームに移植するには、以下を実装します：

1. **イベントループ** — `get_interest().next_timer_ms` の間隔で `tick()` を呼び出す poll/epoll/kqueue/IOCP
2. **UDP ソケット** — UDP ソケットの作成・バインド・読み取り、受信データを `on_socket_recv()` に渡す
3. **TUN デバイス** — プラットフォーム固有の TUN を作成、`tun_output` コールバックからのパケットを書き込み、読み取ったパケットを `on_tun_packet()` に渡す
4. **ルーティング** — TUN デバイス経由でトラフィックを誘導するルートを設定
5. **DNS** — DNS リークを防止する DNS 設定

リファレンス実装として `src/platform/linux/platform_linux.c` を参照してください。
