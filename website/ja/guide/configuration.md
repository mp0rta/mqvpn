# 設定

mqvpn は INI と JSON の両方の設定ファイルに対応しています。ファイルの拡張子（`.conf` で INI、`.json` で JSON）から形式を自動判別します。CLI 引数は設定ファイルの値を上書きします。

## INI 形式

### サーバー

```ini
# /etc/mqvpn/server.conf
[Interface]
Listen = 0.0.0.0:443
Subnet = 10.0.0.0/24
Subnet6 = 2001:db8:1::/112

[TLS]
Cert = /etc/mqvpn/server.crt
Key = /etc/mqvpn/server.key

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Multipath]
Scheduler = wlb
```

### クライアント

```ini
# /etc/mqvpn/client.conf
[Server]
Address = 203.0.113.1:443

[Auth]
Key = mPyVpoQWcp/5gr404xvS19aRC03o0XS2mrb2tZJ1Ii4=

[Interface]
TunName = mqvpn0
DNS = 1.1.1.1, 8.8.8.8
LogLevel = info

[Multipath]
Scheduler = wlb
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
  "scheduler": "wlb"
}
```

### クライアント

```json
{
  "mode": "client",
  "server_addr": "203.0.113.1:443",
  "auth_key": "<YOUR_PSK_HERE>",
  "insecure": false,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "kill_switch": false,
  "reconnect": true,
  "reconnect_interval": 5,
  "scheduler": "wlb",
  "paths": ["eth0", "wlan0"]
}
```

## マルチユーザー認証

サーバーでは複数のユーザーをそれぞれ個別の PSK で認証できます。JSON config の `users` 配列で設定するか、[Control API](#control-api) を使って実行中にユーザーを管理できます。

`auth_key`（グローバルキー）と `users` を両方設定した場合、クライアントはどちらでも認証可能です。名前付きユーザーのみに制限するには、`auth_key` を設定から削除してください。

## 設定ファイルでの実行

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/server.json
```

## 設定リファレンス

### `[Server]`（クライアントのみ）

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Address` | サーバーアドレス（`IP:PORT`） | 必須 |
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

### `[TLS]`（サーバーのみ）

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Cert` | TLS 証明書パス（PEM） | 必須 |
| `Key` | TLS 秘密鍵パス（PEM） | 必須 |

### `[Auth]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Key` | 事前共有鍵（base64、`mqvpn --genkey` で生成） | 必須 |

### `[Multipath]`

| キー | 説明 | デフォルト |
|------|------|-----------|
| `Scheduler` | スケジューラアルゴリズム（`minrtt` または `wlb`） | `wlb` |
| `Path` | バインドするネットワークインターフェース（複数指定可） | デフォルトインターフェース |

スケジューラの詳細は[マルチパス](./multipath)を参照してください。

## Control API

稼働中のサーバーに対して、ローカル TCP ソケット経由で JSON コマンドを送ることで、再起動なしにユーザーの追加・削除などの管理操作が行えます。

### 有効化

```bash
sudo mqvpn --mode server ... --control-port 9090
```

デフォルトでは `127.0.0.1` にバインドされます。認証機能はないため、信頼できるインターフェースのみにバインドしてください。

### コマンド

ユーザーの追加：

```bash
echo '{"cmd":"add_user","name":"carol","key":"carol-secret"}' | nc 127.0.0.1 9090
```

ユーザーの削除：

```bash
echo '{"cmd":"remove_user","name":"carol"}' | nc 127.0.0.1 9090
```

ユーザー一覧の取得：

```bash
echo '{"cmd":"list_users"}' | nc 127.0.0.1 9090
```

統計情報の取得：

```bash
echo '{"cmd":"get_stats"}' | nc 127.0.0.1 9090
```

すべてのコマンドは `"ok"` フィールドを含む JSON レスポンスを返します。

## systemd

先にバイナリとユニットファイルをインストールします（初回のみ）：

```bash
sudo cmake --install build --prefix /usr/local
```

### サーバー

```bash
sudo cp systemd/server.json.example /etc/mqvpn/server.json
# /etc/mqvpn/server.json を編集
sudo systemctl enable --now mqvpn-server
```

### クライアント（テンプレートユニット）

クライアントはテンプレートユニットを使用します。インスタンス名が設定ファイル名に対応します：

```bash
sudo cp systemd/client.json.example /etc/mqvpn/client-home.json
sudo systemctl enable --now mqvpn-client@home
# /etc/mqvpn/client-home.json を読み込みます
```
