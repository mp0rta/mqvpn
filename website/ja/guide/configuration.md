# 設定

mqvpn は INI 形式の設定ファイルを使用します。CLI 引数は設定ファイルの値を上書きします。

## サーバー設定

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

## クライアント設定

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

## 設定ファイルでの実行

```bash
sudo mqvpn --config /etc/mqvpn/server.conf
sudo mqvpn --config /etc/mqvpn/client.conf
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

## systemd

### サーバー

```bash
sudo cp systemd/server.conf.example /etc/mqvpn/server.conf
# /etc/mqvpn/server.conf を編集
sudo systemctl enable --now mqvpn-server
```

### クライアント（テンプレートユニット）

クライアントはテンプレートユニットを使用します。インスタンス名が設定ファイルに対応します：

```bash
sudo cp systemd/client.conf.example /etc/mqvpn/client-home.conf
sudo systemctl enable --now mqvpn-client@home
# /etc/mqvpn/client-home.conf を読み込みます
```
