# Proxy + Tor stream isolation: cross-app implementation brief

Drop this into any app that holds the INTERNET permission and makes its own
outbound requests. It describes one feature to add consistently everywhere:
an optional SOCKS5 / Tor proxy for all of the app's traffic, including a
username and password pair for Tor stream isolation ("traffic separation").

Adapt the naming and UI to the app you are in. Do not change the crypto core
or any wire format. Where an app is owned or co-planned by someone else, get
their sign-off before merging.

## What "traffic separation" means here

The user's request for a username and password field is Tor stream isolation.
Tor's SOCKS port treats the SOCKS username/password pair as an isolation token
(IsolateSOCKSAuth), so giving an app its own credentials puts its traffic on a
separate Tor circuit from every other app sharing the same proxy. For a real
authenticated SOCKS5 proxy the same fields are ordinary credentials. Either
way they are optional.

## Behavior spec (platform independent)

- Modes: Off (default), Orbot (Tor), Custom.
  - Off: direct connections, current behavior unchanged.
  - Orbot: SOCKS5 to 127.0.0.1:9050 (Orbot's default listener).
  - Custom: user supplied SOCKS5 host and port.
- Optional SOCKS5 username and password, blank by default. Available for both
  Orbot and Custom (Tor isolation applies to Orbot too). A nonempty pair is
  sent as SOCKS5 user/pass auth; blank means no auth.
- Fail-closed: when a proxy is enabled and unreachable, requests FAIL. Never
  fall back silently to a direct connection. This is the whole point of the
  feature and must hold on every path.
- Onion mirror: include only if the app's own backend has a first-party
  .onion. Do not invent onion addresses. Most apps omit this.
- Timeouts: extend under a proxy, since Tor adds latency.
- Config lives in the app's existing settings store. Build one shared client
  and rebuild it only when the proxy config changes (compare by a small
  signature string).

## Coverage requirement

The proxy must cover ALL outbound traffic the app makes, not just the primary
call path: API calls, key or directory lookups, WKD, push registration,
update checks, and any background workers. Route every network path through
the single shared client so one switch covers everything. A single missed
path is a leak.

## Platform notes

### Android, OkHttp

- Set `proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(host, port)))` on the
  client builder. OkHttp keeps the target hostname unresolved for a SOCKS
  proxy, so the proxy resolves DNS (no local DNS leak while Tor is active).
- Fail-closed is inherent: a dead proxy throws IOException, which the call
  sites already surface as a network error. Do not add a direct-retry path.
- SOCKS5 auth: Java does not expose per-client SOCKS credentials cleanly. Use
  a process-global `java.net.Authenticator` scoped to the proxy host, or a
  small manual SOCKS5 handshake. Confirm isolation on-device (see testing).
- Manifest: add the Orbot package query for Android 11+ visibility:
  `<queries><package android:name="org.torproject.android" /></queries>`.
- Reference: BurnPony's `ProxyPrefs` + `HttpClientFactory` is the OkHttp
  template.

### Android / JVM, Ktor

- Set `proxy = ProxyBuilder.socks(host, port)` on the engine. Same fail-closed
  behavior, same extended timeouts.
- SOCKS5 auth is similarly awkward and may need engine-level handling; treat
  it the same way as the OkHttp note above and verify on-device.
- Reference: PGPony's `ProxyPrefs` + `HttpClientFactory` is the Ktor template.

### iOS

- URLSession does NOT support SOCKS5. Do not add a SOCKS field that URLSession
  cannot honor. Two real options, both a design decision for a human:
  - Rely on Orbot's system VPN, which routes everything at the OS level and
    needs no in-app proxy field.
  - Embed Tor (Tor.framework) and run a local SOCKS port behind a custom
    transport, since URLSession still will not talk SOCKS directly.
- Flag this for review rather than implementing a fake field.

## UI requirements

Add a Proxy section to Settings, matching the app's existing style:

- Mode selector: Off / Orbot (Tor) / Custom.
- Custom host and port fields, shown when Custom is selected.
- Optional username and password fields, shown for Orbot and Custom.
- An "Orbot not installed" hint when Orbot is selected and its package is
  absent.
- A short fail-closed note: when the proxy is unreachable, requests fail
  rather than falling back to a direct connection.
- Localize new strings; English default at minimum.

## Correctness and security requirements

- No DNS leak: the target hostname must resolve at the proxy, not on device.
- Fail-closed verified: with the proxy enabled, kill it and confirm requests
  fail instead of going direct.
- Stream isolation verified on-device with Tor: distinct username/password
  pairs land on distinct circuits.
- No change to the crypto core or the wire format.
- Proxy Off by default so no existing user's connectivity changes on update.

## Testing checklist

- [ ] Off mode behaves exactly as before.
- [ ] Orbot mode routes through 127.0.0.1:9050 when Orbot is running.
- [ ] Custom SOCKS5 host/port routes correctly.
- [ ] Dead proxy fails the request (no direct fallback) on every network path.
- [ ] Username/password produces an isolated Tor circuit (traffic separation).
- [ ] No DNS query for the target leaves the device while a proxy is active.
- [ ] Settings change takes effect without an app restart.
