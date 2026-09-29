# アーキテクチャ

mqvpn は **[sans-I/O](https://sans-io.readthedocs.io/) C ライブラリ**（`libmqvpn`）として構築されており、その上にプラットフォーム固有のレイヤーを重ねる設計です。VPN プロトコルエンジンとすべての I/O 操作を分離することで、あらゆるプラットフォームへの移植を可能にしています。

## Sans-I/O 設計

ライブラリはプラットフォーム固有のイベントループやデバイス管理を内包せず、トンネルが使う UDP ソケットを送受信のどちらの方向でも持ちません。`tick()` と入力注入 API で駆動され、受信した UDP データグラムや TUN パケットは `on_socket_recv()` / `on_tun_packet()` で注入されます。UDP の送信はすべて、プラットフォームがパスごとに登録するトランスポート ops（サーバーでは共有の 1 つ）を通ります。例外はサーバー側の[ハイブリッド TCP レーン](./hybrid-mode)で、中継する TCP 接続はライブラリ自身が開きます。通常の UDP ソケット向けには、その ops の実装が 2 つ同梱されています — POSIX 版（Linux の GSO / `sendmmsg` バッチ送信を含む）と Winsock 版です。プラットフォームはソケットを作成・バインド・クローズし、読み取り可能になったらトランスポートに読ませます。

```
┌──────────────────────────────────────────────────────────────────┐
│  Platform Layer (owns I/O and the UDP sockets)                   │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │Linux CLI │ │macOS CLI │ │ Android  │ │ iOS (NE) │ │ Windows  │ │
│ │(libevent)│ │(libevent)│ │ (poll)   │ │(RunLoop) │ │(libevent)│ │
│ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ │
│      │ tick()     │ tick()     │ tick()     │ tick()     │ tick()│
├──────┴────────────┴────────────┴────────────┴────────────┴───────┤
│  libmqvpn (event-loop agnostic, owns no UDP socket)              │
│  ┌──────────────────────────────────┐ ┌────────────────────────┐ │
│  │ core engine                      │ │ bundled transports     │ │
│  │ mqvpn_client.c / mqvpn_server.c  │ │ bind/posix.c           │ │
│  │ mqvpn_config.c / auth.c          │ │ bind/winsock.c         │ │
│  │ path_state_machine.c             │ │ (transport ops for     │ │
│  │ flow_sched.c / addr_pool.c       │ │  UDP sockets)          │ │
│  └────┬─────────────────────────────┘ └────────────────────────┘ │
│       │ xquic callbacks                                          │
├───────┴──────────────────────────────────────────────────────────┤
│  xquic (QUIC / HTTP/3 / MASQUE engine)                           │
│  BoringSSL (TLS 1.3)                                             │
└──────────────────────────────────────────────────────────────────┘
```

Apple プラットフォームでは 2 つのエントリポイントが異なる構成を取ります: macOS CLI は Darwin プラットフォーム層（`src/platform/darwin/`、libevent イベントループ + `utun` デバイス）を使う一方、iOS Network Extension は sans-I/O コアを Swift で直接ラップします — RunLoop タイマー駆動の専用 tick スレッドで、パケットは `NEPacketTunnelFlow` 経由でやり取りします（libevent も独自の `utun` 操作も使いません）。

### Sans-I/Oである理由

- **移植性** — 各プラットフォームが独自のイベントループ（Linux / macOS / Windows では libevent、Android では専用エンジンスレッド上の `poll()` リアクター、iOS では Network Extension 内の専用 RunLoop スレッド）を提供します。ライブラリはスレッドモデルを強制しません。
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

// 2. ネットワークパスの追加: プラットフォームが UDP ソケットを開いてバインドし
//    （必要ならインターフェースに固定）、同梱の POSIX トランスポートで包んで
//    登録する。ライブラリはソケットを借りるだけで、クローズはしない。
int fd = socket(AF_INET, SOCK_DGRAM, 0);
bind(fd, (struct sockaddr *)&local, sizeof(local));

mqvpn_bind_posix_opts_t bopts = {.struct_size = sizeof(bopts)};
void *tctx;
mqvpn_bind_posix_path_new(fd, &bopts, &tctx);
mqvpn_path_handle_t path =
    mqvpn_client_add_path(client, &desc, mqvpn_bind_posix_path_ops(), tctx, NULL);

// 3. 接続してエンジンを駆動
mqvpn_client_connect(client);

while (running) {
    mqvpn_interest_t interest;
    mqvpn_client_get_interest(client, &interest);
    int next_ms = interest.next_timer_ms;

    poll(fds, nfds, next_ms);

    // 受信した UDP データ: トランスポートがソケットを読み、
    // データグラムを 1 つずつ注入する（mqvpn_client_on_socket_recv）
    if (udp_readable)
        mqvpn_bind_posix_path_drain(tctx, client, path, 64);

    // TUN パケットを注入
    if (tun_readable)
        mqvpn_client_on_tun_packet(client, pkt, len);

    // エンジンを駆動 — キューされた処理を実行し、パスのトランスポート ops で
    // 送信し、コールバックを呼び出し
    mqvpn_client_tick(client);
}
```

## コールバックモデル

ライブラリはコールバックを通じてプラットフォームに通知します：

| コールバック | タイミング | プラットフォームの対応 |
|-------------|-----------|---------------------|
| `tun_output` | 復号されたパケットが準備完了 | TUN デバイスに書き込み |
| `tunnel_config_ready` | サーバーが IP/MTU を割り当て | TUN デバイスを作成・設定 |
| `state_changed` | 接続状態の遷移 | UI 更新、再接続処理 |
| `path_event` | パス状態の変化 | ログ記録、ルーティング調整 |
| `log` | ログメッセージ | ログに書き込み |

UDP の送信はコールバックではありません。クライアントの各パスは、プラットフォームが `mqvpn_client_add_path()` で登録するトランスポート ops のテーブルを持ちます: `send`（必須 — データグラムの束を受け取り、受け付けた数、またはブロックする・失敗したことを返す）、`get_stats` と `release`（任意）。サーバーは `mqvpn_server_set_transport()` で共有のテーブルを 1 つ登録します。通常の UDP ソケット向けには、同梱の POSIX / Winsock トランスポートがこの ops を実装しています。

すべてのコールバックは、トランスポート ops も含めて、`tick()` を呼び出したスレッドと同じスレッドで呼び出されます — 同期処理は不要です。

## コンポーネント

| コンポーネント | ファイル | 役割 |
|--------------|---------|------|
| クライアントエンジン | `mqvpn_client.c` | QUIC 接続、MASQUE CONNECT-IP、ステートマシン |
| サーバーエンジン | `mqvpn_server.c` | マルチクライアント処理、アドレス割り当て |
| Config ビルダー | `mqvpn_config.c` | Opaque な設定構造、setter 関数、ABI 互換性 |
| パスステートマシン | `path_state_machine.c` | パスごとのライフサイクル: 検証、再試行、切断とスロット再利用 |
| フロースケジューラ | `flow_sched.c` | WLB および MinRTT パケットスケジューリング |
| アドレスプール | `addr_pool.c` | サーバー側 IP アドレス割り当て |
| 認証 | `auth.c` | TLS 1.3 上の PSK 認証 |
| 同梱トランスポート | `bind/posix.c`, `bind/winsock.c` | 通常の UDP ソケット向けトランスポート ops（POSIX、Winsock） |

## プラットフォーム移植

mqvpn を新しいプラットフォームに移植するには、以下を実装します：

1. **イベントループ** — `get_interest().next_timer_ms` の間隔で `tick()` を呼び出す poll/epoll/kqueue/IOCP
2. **UDP ソケット** — パスごとに UDP ソケットを作成・バインドし（OS が必要とするならインターフェースに固定）、同梱トランスポート（`mqvpn_bind_posix_path_new()` / `mqvpn_bind_winsock_path_new()` — Windows では先にソケットを non-blocking にする）で包むか `mqvpn_path_ops_t` を自前で実装して、`mqvpn_client_add_path()` で登録する。読み取り可能になったらトランスポートの drain ヘルパーを呼ぶ（または `on_socket_recv()` でデータグラムを渡す）。ソケットはプラットフォームのもので、ライブラリがクローズすることはない
3. **パスの終了処理** — 2 つの契約があります。OS がパスの消失を通知したとき: `mqvpn_client_drop_path()` を呼び、そのパスの I/O を止めてソケットをクローズしてから `mqvpn_client_on_platform_path_released()` を呼ぶ。終了時: 読み取りを止め、`mqvpn_client_destroy()` を呼び（登録済みでまだ解放されていないトランスポートはすべてこの中で後始末される）、そのあとでソケットをクローズする
4. **TUN デバイス** — プラットフォーム固有の TUN を作成、`tun_output` コールバックからのパケットを書き込み、読み取ったパケットを `on_tun_packet()` に渡す
5. **ルーティング** — TUN デバイス経由でトラフィックを誘導するルートを設定
6. **DNS** — DNS リークを防止する DNS 設定
