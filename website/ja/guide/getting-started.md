# はじめに

mqvpn は MASQUE CONNECT-IP (RFC 9484) を使用し、Multipath QUIC 上で標準準拠の IP トンネリングを実現するマルチパス QUIC VPN です。

## インストール

### サーバー（ワンクリックセットアップ）

Ubuntu/Debian の VPS で以下を実行すると、バイナリのインストールから証明書・認証キー・設定ファイルの生成までを一括で行います。

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
install.sh は自己署名証明書を生成します。クライアント接続時には `--insecure` が必要です。本番環境では Let's Encrypt などの信頼された証明書に置き換え、`--insecure` を省略してください。
:::

### クライアント（deb パッケージ）

[Releases](https://github.com/mp0rta/mqvpn/releases/latest) から `.deb` をダウンロードしてインストールします。

```bash
# VERSION と ARCH は環境に合わせて置き換えてください（例: 0.5.0, amd64）
curl -LO https://github.com/mp0rta/mqvpn/releases/latest/download/mqvpn_VERSION_ARCH.deb
sudo dpkg -i mqvpn_*.deb
```

### ソースからビルド

ソースからビルドする場合は[ビルド](./building)を参照してください。

## クイックスタート

インストールが済んだら、クライアントからサーバーに接続します。サーバーの install.sh 出力に表示された認証キーとアドレスを使います。

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
  --insecure             信頼されていない証明書を受け入れる（テスト用）
  --tun-name NAME        TUN デバイス名（デフォルト: mqvpn0）
  --listen BIND:PORT     リッスンアドレス（サーバー、デフォルト: 0.0.0.0:443）
  --subnet CIDR          クライアント IPv4 プール（サーバー）
  --subnet6 CIDR         クライアント IPv6 プール（サーバー）
  --cert PATH            TLS 証明書（サーバー）
  --key PATH             TLS 秘密鍵（サーバー）
  --scheduler minrtt|wlb マルチパススケジューラ（デフォルト: wlb）
  --max-clients N        最大同時接続クライアント数（サーバー、デフォルト: 64）
  --control-port PORT    Control API の TCP ポート（サーバー）
  --control-addr ADDR    Control API のバインドアドレス（デフォルト: 127.0.0.1）
  --status               サーバーの稼働状況を Control API 経由で表示して終了
  --log-level LVL        ログレベル（debug|info|warn|error）
  --no-reconnect         自動再接続を無効化（クライアント）
  --kill-switch          VPN 外への通信を遮断（クライアント）
  --genkey               PSK を生成して終了
  --help                 すべてのオプションを表示
```

`--config` を指定した場合、`--mode` は設定ファイル内容から自動判定されます。CLI 引数は設定ファイルの値を上書きします。

## 次のステップ

- [ビルド](./building) — Linux、Windows、Android でのソースからのビルド
- [設定](./configuration) — 設定ファイルリファレンス
- [マルチパス](./multipath) — マルチパスのセットアップとスケジューラオプション
