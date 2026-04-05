# はじめに

mqvpn は MASQUE CONNECT-IP (RFC 9484) を使用し、Multipath QUIC 上で標準準拠の IP トンネリングを実現するマルチパス QUIC VPN です。

## 前提条件

- Linux（カーネル 3.x 以降、TUN サポートあり）
- CMake 3.10+
- GCC または Clang（C11）
- libevent 2.x

## クイックスタート

### 1. ビルド

```bash
git clone --recurse-submodules https://github.com/mp0rta/mqvpn.git
cd mqvpn && ./build.sh
```

詳しい手順や他のプラットフォームについては[ビルド](./building)を参照してください。

### 2. サーバーの起動

```bash
sudo scripts/start_server.sh
# → Generated auth key example: mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=
```

`start_server.sh` は自己署名証明書を生成し、NAT/フォワーディングを設定してサーバーを起動します。

::: warning
サーバーは UDP で待受ポートを開放する必要があります（デフォルト: 443、`--listen` で変更可能）。クライアントのすべてのトラフィックはトンネル経由でルーティングされます（TUN デバイスによるデフォルトルート）。
:::

デュアルスタック（IPv4 + IPv6）の場合：

```bash
sudo scripts/start_server.sh --subnet 10.0.0.0/24 --subnet6 fd00:abcd::/112
```

### 3. クライアントの接続

シングルパス：

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= --insecure
```

マルチパス（2つのインターフェース）：

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --path eth0 --path wlan0 --insecure
```

DNS オーバーライド付き（DNS リーク防止）：

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4= \
    --dns 1.1.1.1 --dns 8.8.8.8 --insecure
```

::: tip
`--insecure` は TLS 証明書検証をスキップします（自己署名証明書用）。本番環境では信頼された証明書（例: Let's Encrypt）を使用し、`--insecure` を省略してください。
:::

::: tip
`--path` を指定しない場合、クライアントはデフォルトインターフェースを使用します（シングルパスモード）。マルチパスには2つ以上の `--path` フラグが必要です。詳しくは[マルチパス](./multipath)を参照してください。
:::

## 認証キーの生成

```bash
mqvpn --genkey
```

または `start_server.sh` に自動生成させることもできます。

## CLI リファレンス

```
mqvpn --config PATH
mqvpn --mode client|server [options]

  --server IP:PORT       サーバーアドレス（クライアント）
  --path IFACE           マルチパスインターフェース（複数指定可）
  --auth-key KEY         PSK 認証
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
