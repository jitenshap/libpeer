# ESP32 I2S Mic to Browser

ESP32 に接続したマイク音声を、WebRTC でブラウザーへ送るサンプルです。

ESP32 側は WebSocket シグナリングを使ってブラウザーと接続し、音声トラックとデータチャンネルを張ります。ブラウザー側は STUN / TURN / TURNS を使った `RTCPeerConnection` で受けます。

## できること

- ESP32 の I2S マイク音声をブラウザーへ送信
- WebSocket シグナリングで Offer / Answer / ICE candidate を交換
- データチャンネルの送受信
- `menuconfig` でボード定義を切り替え
- Seeed XIAO ESP32S3 Sense の PDM マイクに対応
- ESP32-S3 では MSM261 系 I2S マイク向けの初期設定を同梱

カメラ機能はこの派生では対象外です。

## 対応ボード

`main/Kconfig.projbuild` で次のボード定義を選べます。

- `ESP32-EYE`
- `ESP32S3-EYE`
- `M5STACK-CAMERA-B`
- `ESP32S3-XIAO-SENSE`
- `Generic ESP32-S3 Board`

音声入力は選択したボードに応じて切り替わります。

- `Generic ESP32-S3 Board` では `PDM microphone` または `I2S microphone (MSM261S4030H0)` を選択可能
- `Generic ESP32-S3 Board` で `PDM microphone` を選ぶ場合の既定ピンは XIAOと同様 `CLK=GPIO 42`、`DATA=GPIO 41`
- `ESP32S3-XIAO-SENSE` は PDM マイク前提
- `ESP32-EYE` / `ESP32S3-EYE` / `M5STACK-CAMERA-B` はたぶんマイクがないのでDatachannel接続ができるだけです  

## ESP32-S3 のデフォルト設定

`sdkconfig.defaults.esp32s3` は汎用の ESP32-S3 ボードに MSM261 を接続して使うための初期設定として使えます。

- `CONFIG_GENERIC_ESP32S3_BOARD=y`
- `CONFIG_AUDIO_INPUT_I2S_MSM261=y`
- `CONFIG_AUDIO_CODEC_OPUS=y`
- `CONFIG_AUDIO_INPUT_GAIN=20`
- `CONFIG_AUDIO_I2S_BCLK_GPIO=9`
- `CONFIG_AUDIO_I2S_WS_GPIO=45`
- `CONFIG_AUDIO_I2S_DATA_GPIO=8`

この構成をそのまま使う場合は、MSM261 を GPIO 9 / 45 / 8 に接続します。ピン定義や音量は `menuconfig` から変更できます。

## シグナリング

`signaling/` に次のものを入れています。

- `signaling_server.js`
  - Node.js の WebSocket エコー/中継サーバー
  - 接続先パスごとに部屋を分け、同じ room 内のクライアントにメッセージを中継
- `index.html`
  - ブラウザー側のサンプル UI
  - Offer / Answer / ICE candidate の確認
  - データチャンネル送受信
  - 遠隔音声の再生確認

ESP32 側は `CONFIG_SIGNALING_URL` でシグナリング先を指定します。

## 使い方

### 1. リポジトリを取得する

```bash
git clone https://github.com/jitenshap/libpeer
cd libpeer/examples/esp32_i2smic2browser
```

### 2. 対象の ESP32 を選ぶ

```bash
idf.py set-target esp32s3
```

`esp32`、`esp32s3` など、使うボードに合わせて対象を切り替えてください。

### 3. `menuconfig` を開く

```bash
idf.py menuconfig
```

主に次を設定します。

- `Peer Example Configuration -> Board model`
- `Peer Example Configuration -> Audio input type`
- `Peer Example Configuration -> Signaling URL`
- `Peer Example Configuration -> Signaling Token`
- `Peer Example Configuration -> Use TURN server`
- `Example Connection Configuration -> Wi-Fi SSID`
- `Example Connection Configuration -> Wi-Fi Password`

`Generic ESP32-S3 Board` を選んだ場合は、I2S ピンもここで変更できます。

### 4. ビルドする

```bash
idf.py build
```

### 5. フラッシュする

```bash
idf.py flash
```

### 6. ブラウザー側を起動する

`signaling/` の Node.js サーバーを起動して、`index.html` をブラウザーで開きます。

```bash
cd signaling
npm install
node signaling_server.js
```

ブラウザー側の `WebSocket URL` にサーバーの URL を入れて接続します。

## 接続の流れ

1. ESP32 が Wi-Fi に接続
2. ESP32 が `CONFIG_SIGNALING_URL` に WebSocket 接続
3. ブラウザーが Offer を送る、または ESP32 側が Offer を生成
4. SDP と ICE candidate を WebSocket で交換
5. WebRTC が接続されると、ESP32 の音声がブラウザーへ流れる
6. データチャンネルも同時に開かれる

## 注意点

- このサンプルは音声用途です。カメラは使いません。
- `CONFIG_USE_TURN_SERVER` を有効にすると、ESP32 側の ICE server に TURN/TURNSサーバー を追加できます。
- `CONFIG_AUDIO_INPUT_GAIN` は 1 から 64 の整数です。音量は動作中に `audiogain` コマンドでも変更できます。
- Wi-Fi 設定は NVS に保存できます。

## コンソールコマンド

起動後の UART コンソールで使えます。

- `reset`
- `wifi_set <ssid> <password>`
- `wifidiscon`
- `wifireconn`
- `wificonn [ssid password]`
- `answer_apply`
- `audiogain [1-64]`
