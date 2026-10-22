# ZeroByte Android SDK

The Kotlin client for ZeroByte, an end-to-end encrypted relay between two
paired devices of one app. It is a plain JVM library: it runs on Android API 28
and newer (the first release with ChaCha20-Poly1305 in the platform) and on any
JVM 11+. It has no runtime dependency beyond the Kotlin standard library, and
HTTP goes through `HttpURLConnection`.

## How it works

Two devices pair once and agree a 32-byte link key and a link id. From these,
each device derives the mailbox name, an access token and one encryption key
per direction. Every message is sealed with ChaCha20-Poly1305 on the device
that sends it. The relay holds the sealed envelope until the other device
collects it, and it never has a key to open it with.

The wire format is specified in
[Relay Protocol v1](https://github.com/zerobyte-cloud/zerobyte-protocol/blob/master/relay-v1.md).

## Installation

The library is not on Maven Central yet. Publish it to your local Maven
repository:

```sh
git clone https://github.com/zerobyte-cloud/zerobyte-android-sdk.git
cd zerobyte-android-sdk
./gradlew publishToMavenLocal
```

Then, in your app:

```kotlin
repositories { mavenLocal() }

dependencies {
    implementation("cloud.zerobyte:zerobyte:1.1.0")
    implementation("cloud.zerobyte:zerobyte-okhttp:1.1.0") // watch and signal sockets
}
```

`zerobyte` depends on the Kotlin standard library only. `zerobyte-okhttp` adds
the WebSockets over OkHttp, since Android has no platform WebSocket client.

## Usage

```kotlin
import cloud.zerobyte.*

// Both devices agreed linkKey (32 bytes) and linkID when they paired.
val credentials = Credentials(linkKey, linkID)
val relay = Relay(
    appID = "<your app id>",
    credentials = credentials,
    base = "https://relay.example.com/v1/", // your relay
)
val link = Link(credentials, Direction.C2P, relay, savedLastReceived)

// The calls block: run them off the main thread.
withContext(Dispatchers.IO) {
    link.send("hello".toByteArray())
    link.receive().forEach { handle(it.plaintext) }
}
```

- **Pairing** is the app's job: for example a QR code carrying a fresh 32-byte
  key, or an ECDH exchange confirmed by comparing digits on both screens. Keep
  the link key in the Android Keystore or encrypted storage.
- **Directions.** The primary holds the source of truth and sends
  `Direction.P2C`; the companion sends `Direction.C2P`.
- **State.** Persist `link.lastReceived` and pass it back on the next start, so
  messages are not delivered twice.
- **Unpairing.** Call `link.erase()` to delete the mailbox at once.
- **The relay.** `base` is your relay's `/v1/` URL, with the trailing slash.
  There is no default.

### Watching for new messages

```kotlin
import cloud.zerobyte.okhttp.*

val watch = relay.watch(okHttp, Direction.P2C, object : WatchListener {
    override fun onOpen() = pull()                   // and after every reconnect
    override fun onSequence(sequence: ULong) = pull()
    override fun onFailure(error: Throwable) = scheduleReconnect()
})
// watch.close() when the app goes to the background
```

The socket sends `ping` every 30 seconds, which keeps NATs open and tells a
relay with push that this device is awake. With another WebSocket client, open
`relay.watchURL(direction)` with the header `Authorization: relay.authorization()`
and the subprotocol `zerobyte.v1`; each text message that is a number is a
sequence.

### Relay extensions

These work on relays and apps that enable them; elsewhere the relay answers
`404` (`RelayException` code `unavailable`). Any call may throw code
`rate_limited` with `retryAfterSeconds`: wait and retry.

**Push.** The reader registers on the direction it reads; the writer asks for
a push per message. On Android the relay's FCM module delivers it:

```kotlin
val token = FirebaseMessaging.getInstance().token.await()
relay.registerPush(Fcm.registration(token, tag, alert = "New data"), Direction.P2C)
link.send(bytes, Notify.ALERT) // on the other device

// FirebaseMessagingService.onMessageReceived: every ZeroByte message is data-only
val push = Fcm.parse(message.data) ?: return
// find the link by push.tag, receive, and for Notify.ALERT show a notification
```

For another push service the relay has, build
`PushRegistration("<service>", mapOf(/* its fields */), tag)`.

**Signal and ICE.** A rendezvous for a direct WebRTC connection. Frames are
sealed under signal keys derived from the link key; the relay cannot read or
forge them.

```kotlin
val signal = relay.signal(okHttp, Direction.P2C, object : SignalListener {
    override fun onPeer(present: Boolean) { if (present) signal.send(offer) }
    override fun onMessage(data: ByteArray) = handle(data)
})
val ice = relay.iceServers() // STUN/TURN for PeerConnection
```

Without OkHttp, route the messages of `relay.signalURL(sends)` through
`relay.signalSession(sends)`.

The app id identifies your app on your relay. Generate one with
`npm run app-id` in a clone of
[zerobyte-relay](https://github.com/zerobyte-cloud/zerobyte-relay) and add it
to `RELAY_APPS`.

## Testing

```sh
./gradlew test
```

The tests run on the JVM: protocol vectors and `Link`. To also test against a
real relay, start one locally (see zerobyte-relay) and run:

```sh
RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<app id> ./gradlew test
```

For the extensions, add an app with `signal` and `push=<topic>` and set
`RELAY_SIGNAL_APP=<that app id>` as well.

`zerobyte/src/test/resources/relay-v1.json` is copied from the independent
reference in
[zerobyte-protocol](https://github.com/zerobyte-cloud/zerobyte-protocol/tree/master/spec).
Never regenerate it from this library.

## Licence

Apache-2.0, see [`LICENSE`](LICENSE).

## About ZeroByte

ZeroByte is an open-source project by Szymon Michalik: the protocol, the relay
and the SDKs. To use ZeroByte in your app, run your own relay (see
[zerobyte-relay](https://github.com/zerobyte-cloud/zerobyte-relay)) or register the app on
the hosted relay at [console.zerobyte.cloud](https://console.zerobyte.cloud).
