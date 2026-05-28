# マルチパス

mqvpn は [Multipath QUIC](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) を使用して、複数のネットワークパスで同時にトラフィックを転送します。これにより以下が可能になります：

- **シームレスなフェイルオーバー** — あるパスがダウンしても、残りのパスでトラフィックが継続します。切り替え中に短い遅延が発生する場合があります。
- **帯域集約** — 複数インターフェースの帯域幅を組み合わせます（例: WiFi + LTE）。複数の同時フローがある場合に最も効果的です。単一の TCP フローではフローピンにより帯域集約の効果が限定される場合があります。

## マルチパスのセットアップ

### CLI

`--path` で各ネットワークインターフェースを指定します：

```bash
sudo ./build/mqvpn --mode client --server 203.0.113.1:443 \
    --auth-key <key> --path eth0 --path wlan0
```

### 設定ファイル

```ini
[Multipath]
Scheduler = wlb
Path = eth0
Path = wlan0
```

::: tip
`--path` フラグや `Path` エントリを指定しない場合、mqvpn はデフォルトインターフェースを使用します（シングルパスモード）。
:::

## スケジューラ

スケジューラはパケットをパス間でどのように分配するかを決定します。mqvpn は以下のスケジューラをサポートしています：

### WLB（Weighted Load Balancing）— デフォルト

WLB は、パス重み付けとフロー考慮スケジューリングを組み合わせた方式です：

- ロス率・RTT・cwnd などの実測値から各パスの推定スループットを算出し、トラフィック分配比率として使用
- deficit ベースの WRR でアクティブなパスへトラフィックを分配
- VPN トンネル内の並び替えを抑えるため、内部 TCP フロー（flow hash）をパスにピン留め
- ピン留め先が一時的に cwnd ブロックされた場合は、恒久的な再ピン留めなしで spillover
- 非 Datagram 系パケットや、有効なスケジューラ対象パスがない場合は MinRTT にフォールバック

```bash
--scheduler wlb
```

### WLB UDP Pin（`wlb_udp_pin`）

WLB の派生で、内部 TCP フローだけでなく内部 UDP フローも 5-tuple ハッシュで
パスにピン留めします。単一のパケット番号空間で輻輳制御を行う内部プロトコル
（QUIC、SRT、WireGuard、MASQUE 内の QUIC など）をトンネリングする場合に使用
します。外側スケジューラが非対称 RTT のパスにパケットを分散すると、内部 CC
が kPacketThreshold で誤検知して spurious retransmit を起こし cwnd が崩壊
する——TCP と同じ失敗モードを UDP プロトコルでも招きます。

```bash
--scheduler wlb_udp_pin
```

**使うべき場面**: 内部 QUIC、SRT、WireGuard、または単一のシーケンス空間で
独自の輻輳制御を行う UDP プロトコル全般。

**使うべきでない場面**: 短命 UDP フローが非常に多いワークロード（高レート
DNS、mDNS バーストなど）。xquic の WLB フローテーブルは固定 4096 エントリの
オープンアドレス構造で 60 秒のアイドルエビクションを行うため、probe 領域の
圧力下で短命フローの churn により長命の内部フローが追い出される可能性が
あります。`wlb_udp_pin` は、長命の内部 UDP フローを中小規模で抱えるトンネル
向けです。アプリケーション側が並び替えを許容するメディア中心の用途
（WebRTC/SRTP、ゲーム、DNS）では、通常の `wlb` の方が帯域集約効率が
向上します。

### MinRTT（Minimum Round-Trip Time）

MinRTT は各パケットを現在の RTT が最も低いパスで送信します。よりシンプルですが、利用可能な帯域幅を効率的に活用できない場合があります。

- レイテンシを最適化（スループットより優先）
- シンプルなアルゴリズム、予測可能な動作

```bash
--scheduler minrtt
```

### Backup FEC (experimental)

通常のトラフィックを AVAILABLE パスに送り、FEC リペアシンボルを STANDBY
パスに送ります。プライマリリンクがロスしやすく（例: 不安定な WiFi）、
スタンバイがより信頼できる（例: LTE）構成向けに設計されています。

```
--scheduler backup_fec
```

**使うべき場面**: ロスの多い環境での WiFi+LTE マルチパス。スタンバイパス上の
リペアシンボルにより、再送 RTT を待たずにプライマリパスのロスを即座に回復
できます。

**使うべきでない場面**:

- シングルパス構成（スタンバイパスがない = リペアシンボルの送り先がない）
- 帯域集約を狙う高帯域シナリオ（代わりに `wlb` を使用）
- 両端点が mqvpn 0.4.0 以上で、FEC ビルド
  (`-DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON`) が有効である必要があります

**チューニング**: デフォルトは XOR FEC でブロックあたり約 33% のオーバーヘッド
（`src/mqvpn_scheduler.h` の `MQVPN_FEC_*` マクロ参照）。本実験リリースでは
FEC パラメータの CLI フラグは公開されていません。

**性能**: ロス率 1%〜10% における WLB との実測スループット比較は
[週次ベンチマーク](../benchmarks/weekly)を参照。

### どのスケジューラを使うべきか？

| シナリオ | 推奨 |
|----------|------|
| 一般的な用途、帯域集約 | **WLB** |
| 内部 QUIC / SRT / WireGuard トンネル | **`wlb_udp_pin`** |
| レイテンシ重視のアプリケーション | MinRTT |
| 非対称パス（異なる速度） | **WLB** |
| 同程度の速度のパス | どちらでも可 |
| ロスの多いプライマリ + 信頼できるスタンバイ（実験的） | `backup_fec` |

## 動的パス管理

libmqvpn API では、VPN の実行中にパスを追加・削除できます。これはモバイル環境でネットワークインターフェースが動的に変化する場合に有用です（例: LTE 接続中に WiFi に接続）。

ライブラリレベルでは、プラットフォームが `mqvpn_client_add_path_fd()` を使用して新しい UDP ソケットをパスとして追加し、パスマネージャがライフサイクルを自動的に管理します。パスが削除される（インターフェースがダウンする）と、トラフィックは残りのパスにシームレスに移行します。

標準 CLI では、起動時に `--path` フラグでパスを指定する方式です（実行中のインターフェース監視による自動追加/削除は未実装）。起動時に登録済みの複数パスがある場合は、障害時に残りのパスへフェイルオーバーします。

## パスの重み付け

WLB はトランスポートの実測値からパス重みを自動更新します。手動で重みを設定する必要はありません。

仕組み：
- **ロス率・RTT・cwnd** から各パスの推定スループットを算出し、パス間のトラフィック分配比率（重み）として使用します
- deficit WRR が、その重みに基づいてパケット/フローの割り当てを行います
- 既存の TCP フローピンは再利用され、アイドル・高ロス・パス障害時にはエントリを破棄します
- ラウンド境界やパス復帰イベントで重み/deficit を更新します

これにより、非対称パス（例: 300 Mbps 有線 + 80 Mbps 無線）が手動チューニングなしで効率的に活用されます。

## 仕組み

```
┌─────────────────┐                          ┌─────────────────┐
│   Application   │                          │    Internet     │
├─────────────────┤                          ├─────────────────┤
│   TUN (mqvpn0)  │                          │   TUN (mqvpn0)  │
├─────────────────┤                          ├─────────────────┤
│  MASQUE         │    HTTP Datagrams        │  MASQUE         │
│  CONNECT-IP     │◄──(Context ID = 0)──────►│  CONNECT-IP     │
├─────────────────┤                          ├─────────────────┤
│  Multipath QUIC │◄── Path A (eth0)  ──────►│  Multipath QUIC │
│                 │◄── Path B (wlan0) ──────►│                 │
├─────────────────┤                          ├─────────────────┤
│  UDP (eth0/wlan)│                          │   UDP (eth0)    │
└─────────────────┘                          └─────────────────┘
     Client                                      Server
```

各パスは特定のネットワークインターフェースにバインドされた個別の UDP ソケットです。Multipath QUIC が QUIC レイヤーでパスを管理し、サーバーからは複数のパスを持つ単一の QUIC 接続として認識されます。

## ベンチマーク

非対称デュアルパス環境（300 Mbps + 80 Mbps、netem によるエミュレーション）でのフェイルオーバーおよび帯域集約の計測結果は、[ベンチマークレポート](https://github.com/mp0rta/mqvpn/blob/main/docs/benchmarks_netns.md)を参照してください。

## プロトコル標準

| プロトコル | 仕様 |
|-----------|------|
| MASQUE CONNECT-IP | [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484) |
| HTTP Datagrams | [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297) |
| QUIC Datagrams | [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) |
| Multipath QUIC | [draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/) |
| HTTP/3 | [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114) |
