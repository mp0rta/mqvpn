# はじめに

mqvpn は MASQUE CONNECT-IP (RFC 9484) と、Multipath QUIC をベースとしたL3 マルチパス VPN です。

## インストール

### サーバー

#### Debian / Ubuntu（deb パッケージ）

`mqvpn` deb にはクライアントとサーバーの両方で使う VPN プログラムが含まれ、`mqvpn-server` deb はサーバーのサービス・NAT 設定・初回設定を追加します。[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から同じバージョンの `mqvpn` と `mqvpn-server` の deb をダウンロードし、両方をインストールします。

```bash
# VERSION と ARCH は環境に合わせて置き換えてください（例: 0.19.3, amd64）
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn_VERSION_ARCH.deb
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn-server_VERSION_ARCH.deb
sudo apt install ./mqvpn_VERSION_ARCH.deb ./mqvpn-server_VERSION_ARCH.deb
```

インストール時に証明書・認証キー・設定ファイルを生成し、サーバーを起動して OS 起動時の自動起動も登録します。証明書や設定ファイルがすでにある場合は、そのまま使います。生成される設定ではサーバー側のハイブリッドモードと reorder バッファが有効になっており、クライアント側でも有効にしたときだけ動作します。`AllowClientScheduler = true` も設定されるので、クライアントは自分のダウンロード方向のスケジューラを指定できます。

インストール時に認証キーとクライアント用のコマンドが表示されます。あとから `sudo mqvpn-server-info` で再表示できます。

インストール中には、証明書に使う公開ホスト名（省略可）を尋ねます。クライアント用サブネットは、デフォルトの `10.0.0.0/24` がサーバーのネットワークと重なる場合のみ、ポートは UDP 443 がすでに使用中の場合のみ尋ねます。自動化などで事前に値を指定するには、次のようにします。

```bash
echo 'mqvpn-server mqvpn-server/subnet string 10.8.0.0/24' | sudo debconf-set-selections
sudo env MQVPN_PORT=10020 apt install ./mqvpn_VERSION_ARCH.deb ./mqvpn-server_VERSION_ARCH.deb
```

これらの値は `/etc/mqvpn/server.conf` を新しく生成するときだけ使われます。稼働中のサーバーの設定を変えるには、`/etc/mqvpn/server.conf` を編集して `sudo systemctl restart mqvpn-server` を実行します。

`sudo apt remove mqvpn-server` はサーバーを停止し、`/etc/mqvpn` は残します。`sudo apt purge mqvpn-server` は生成された設定ファイル・認証キー・証明書も削除するため、すべてのクライアントに新しい認証キーが必要になります。自分で作成したファイルは削除されません。詳細は `/usr/share/doc/mqvpn-server/README.Debian` を参照してください。

::: tip 0.19.2 以前からのアップグレード
サーバー用のファイルは `mqvpn` deb から新しい `mqvpn-server` deb に移りました。両方の deb をまとめてインストールしてください。`/etc/mqvpn` の設定はそのまま残ります。以前に install.sh を使っていた場合は、先に `--uninstall` を付けて実行してください（`/etc/mqvpn` は残ります）。
:::

#### その他の Linux ディストリビューション（インストールスクリプト）

以下を実行すると、バイナリを `/usr/local` にインストールし、deb と同じ証明書・認証キー・設定ファイルを生成します。

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh | sudo bash
```

`--start` を付けると、サーバーの起動と OS 起動時の自動起動登録も同時に行います。

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start
```

ポートやサブネットのカスタマイズもオプションで指定できます。

```bash
curl -fsSL https://github.com/mp0rta/mqvpn/releases/latest/download/install.sh \
    | sudo bash -s -- --start --port 10020 --subnet 10.8.0.0/24
```

アンインストールするには `--uninstall` を付けて再実行します（`--purge` で設定ファイルも削除）。

::: warning
どちらのインストール方法でも、サーバーに証明書がない場合は自己署名証明書が生成されます。その証明書では、クライアント接続時に `--insecure` が必要です。本番環境では Let's Encrypt などの信頼された証明書に置き換え、`--insecure` を省略してください。deb はすでにある証明書をそのまま使い、`sudo mqvpn-server-info` は自己署名証明書の場合のみクライアント用コマンドに `--insecure` を付けます。
`--cert` (設定ファイルでは `Cert` / `cert_file`) には fullchain (Let's Encrypt では `fullchain.pem`) を指定してください。クライアントは足りない中間証明書を取りに行きません。
:::

### クライアント（Debian / Ubuntu）

[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から `mqvpn` の deb をダウンロードしてインストールします。

```bash
# VERSION と ARCH は環境に合わせて置き換えてください（例: 0.6.0, amd64）
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn_VERSION_ARCH.deb
sudo dpkg -i mqvpn_*.deb
```

### Windows クライアント

Windows amd64 / arm64 向けにビルド済みバイナリを配布しています。[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から `mqvpn_<VERSION>_windows_<ARCH>.zip` をダウンロードし、展開して同梱の `README.txt` に従ってください（管理者 PowerShell 必須）。

### macOS クライアント

Apple silicon (arm64) 向けにビルド済みバイナリを配布しています。[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から `mqvpn_<VERSION>_darwin_arm64.tar.gz` をダウンロードし、展開して同梱の `README.txt` に従ってください（sudo 必須）。

### ソースからビルド

ソースからビルドする場合は[ビルド](./building)を参照してください。

## クイックスタート

インストールが済んだら、クライアントからサーバーに接続します。サーバーのインストール時に表示された認証キーとアドレスを使います。deb でインストールした場合は `sudo mqvpn-server-info` で再表示できます。

シングルパス：

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --insecure
```

マルチパス（複数インターフェース）：

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --path eth0 --path wlan0 --insecure
```

DNS オーバーライド付き（DNS リーク防止）：

```bash
sudo mqvpn --mode client --server YOUR_SERVER:443 \
    --auth-key YOUR_AUTH_KEY --dns 1.1.1.1 --dns 8.8.8.8 --insecure
```

::: tip
`--path` を指定しない場合、クライアントはデフォルトインターフェースを使います（シングルパス）。マルチパスには2つ以上の `--path` が必要です。詳しくは[マルチパス](./multipath)を参照してください。
:::

::: warning
サーバーは UDP ポート（デフォルト: 443）を開放する必要があります。クライアントのすべてのトラフィックはトンネル経由でルーティングされます。
:::

## 認証キーの生成

```bash
mqvpn --genkey
```

install.sh や `start_server.sh` を使う場合は自動生成されます。

## CLI リファレンス

```
mqvpn --config PATH
mqvpn --mode client|server [options]

  --server HOST:PORT     サーバーアドレス（クライアント、IPv6 は `[2001:db8::1]:443` 形式）
  --path IFACE           マルチパスインターフェース（複数指定可）
  --auth-key KEY         PSK 認証
  --user NAME:KEY        ユーザー個別の PSK（複数指定可、サーバー）
  --dns ADDR             DNS サーバー（複数指定可）
  --tls-server-name NAME TLS SNI / 証明書検証名（クライアント）
  --insecure             信頼されていない証明書を受け入れる（テスト用）
  --tun-name NAME        TUN デバイス名（デフォルト: mqvpn0）
  --listen BIND:PORT     リッスンアドレス（サーバー、デフォルト: 0.0.0.0:443）
  --subnet CIDR          クライアント IPv4 プール（サーバー）
  --subnet6 CIDR         クライアント IPv6 プール（サーバー）
  --cert PATH            TLS 証明書（サーバー）
  --key PATH             TLS 秘密鍵（サーバー）
  --scheduler SCHED      マルチパススケジューラ: minrtt|wlb|wlb_udp_pin|backup_fec
                         （デフォルト: wlb）
  --cc ALGO              輻輳制御アルゴリズム: bbr2|bbr|cubic|none（デフォルト: bbr2）
  --mtu N                TUN MTU（1280-9000、デフォルト: auto）
  --path-mtu N           QUIC パケットのサイズを合わせる経路 MTU（1280-9000、デフォルト: 0）
  --pmtud                経路 MTU を探索する（両端で指定）。--path-mtu が上限になる
  --max-clients N        最大同時接続クライアント数（サーバー、デフォルト: 64）
  --control-port PORT    Control API の TCP ポート（サーバー）
  --control-addr ADDR    Control API のバインドアドレス（デフォルト: 127.0.0.1）
  --status               サーバーの稼働状況を Control API 経由で表示して終了
  --log-level LVL        ログレベル（debug|info|warn|error）
  --no-reconnect         自動再接続を無効化（クライアント）
  --kill-switch          VPN 外への通信を遮断（クライアント）
  --no-manage-routes     ホストのルーティングテーブルを変更しない（クライアント）
  --genkey               PSK を生成して終了
  --version              バージョンを表示して終了
  --help                 すべてのオプションを表示
```

`--config` を指定した場合、`--mode` は設定ファイル内容から自動判定されます。CLI 引数は設定ファイルの値を上書きします。

## 次のステップ

- [ビルド](./building) — Linux、Windows、Android でのソースからのビルド
- [設定](./configuration) — 設定ファイルリファレンス
- [マルチパス](./multipath) — マルチパスのセットアップとスケジューラオプション
