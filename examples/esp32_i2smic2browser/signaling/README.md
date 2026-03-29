# Signaling

`signaling/` には、ESP32 とブラウザーの WebRTC 接続を試すための WebSocket シグナリングサーバーと、ブラウザー側サンプル HTML が入っています。

## サーバーの起動

Node.js を使って起動します。

```bash
cd signaling
npm install
node signaling_server.js
```

サーバーは `ws://0.0.0.0:8000` で待ち受けます。

### 動作

- 接続先のパスごとに room を分けます
- 同じパスに接続したクライアント同士でメッセージを中継します
- つまり、`/room/01` に接続した ESP32 とブラウザーは、`/room/01` 内でだけ通信します

## `index.html` の使い方

`index.html` はブラウザー側のサンプル UI です。

- WebSocket に接続する
- Offer / Answer / ICE candidate をやり取りする
- データチャンネルでメッセージを送る
- ESP32 から届く音声トラックを再生する

### WebSocket URL

画面上部の `WebSocket URL` に、起動したサーバーの URL を入れます。

例:

```text
ws://localhost:8000/room/01
```

ページ URL に `?key=...` が付いている場合だけ、その値が WebSocket URL の末尾に静かに追加されます。`key` は必須ではありません。

## `iceServers` の編集箇所

`index.html` の JavaScript 内に、`RTCPeerConnection` 用の `iceServers` 定義があります。

```js
const DEFAULT_STUN_URLS = [
  "stun:stun.l.google.com:19302",
];
const DEFAULT_TURN_URLS = [
];
const DEFAULT_ICE_USERNAME = "user";
const DEFAULT_ICE_PASSWORD = "password";
```

ここを編集すると、ブラウザー側の既定の ICE サーバーを変更できます。

- `DEFAULT_STUN_URLS`
  - STUN サーバー URL の配列
- `DEFAULT_TURN_URLS`
  - TURN / TURNS サーバー URL の配列
- `DEFAULT_ICE_USERNAME`
  - TURN 認証ユーザー名
- `DEFAULT_ICE_PASSWORD`
  - TURN 認証パスワード

TURN を使う場合は、ここに自分の TURN サーバー URL を追加してください。

## クエリストリングパラメーター

`index.html` は URL のクエリストリングで ICE 設定を上書きできます。

### `stunurls`

STUN サーバー URL のカンマ区切りリストです。

例:

```text
index.html?stunurls=stun:stun.l.google.com:19302,stun:example.com:3478
```

### `turnurls`

TURN / TURNS サーバー URL のカンマ区切りリストです。

例:

```text
index.html?turnurls=turn:example.com:3478?transport=udp,turns:example.com:5349
```

### `iceuser`

TURN 認証のユーザー名です。

例:

```text
index.html?iceuser=user1
```

### `icepassword`

TURN 認証のパスワードです。

例:

```text
index.html?icepassword=secret
```

### 併用例

```text
index.html?stunurls=stun:stun.l.google.com:19302&turnurls=turn:example.com:3478?transport=udp&iceuser=user&icepassword=password
```

## 使い分け

- `DEFAULT_*` を編集すると、この HTML の既定値を変えられます
- クエリストリングを使うと、ファイルを編集せずに実験できます
- ESP32 側とブラウザー側の room を合わせたい場合は、WebSocket URL のパスを同じにしてください

## 補足

- ブラウザー側は SDP を Base64 にして送受信します
- データチャンネルは自動で 1 本作成されます
- 受信した音声はページ内の audio 要素で再生されます
