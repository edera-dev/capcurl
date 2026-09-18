# capcurl

[Object capabilities][ocap] for HTTP requests, bound to a URI and handed over as
a file descriptor.

   [ocap]: https://en.wikipedia.org/wiki/Object-capability_model

capcurl is built on [capsudo-rs][capsudo], and uses the same capability channel
and the same cross-[zone][edera] transport. capsudo delegates running a program.
capcurl delegates making a request.

   [capsudo]: https://github.com/edera-dev/capsudo-rs
   [edera]: https://edera.dev

## Build & test

```
cargo build
cargo test
cargo clippy --all-targets
```

## Using it from the command-line

Run `capcurld -S socket-path-here -U base-uri-here` to bind a credential and a
URI to a socket. That socket is the *object capability*: anyone who can reach it
can make the requests the grant describes, and nothing else.

Run `capcurl -S socket-path-here [target]` to *invoke* it. The daemon hands back
a file descriptor good for exactly one request. The client writes HTTP on it and
reads the answer back.

The client never holds the credential and never names the origin. It supplies a
target relative to the capability, so it cannot ask for a different one.

## Some quick command-line examples

A capability for one repository's issues, with the token read from a file so it
never appears in `ps`:

```
$ capcurld -S /run/cap/gh -U https://api.github.com/repos/edera-dev/capcurl/issues/ \
           -X GET,POST -H 'Authorization: @/run/secrets/gh-token' &
$ capcurl -S /run/cap/gh /42
```

Leave the trailing slash off `-U` and the capability names one exact resource.
The client then supplies no path at all:

```
$ capcurld -S /run/cap/toot -U https://social.example/api/v1/statuses \
           -X POST -H 'Authorization: Bearer @/run/secrets/tok' &
$ capcurl -S /run/cap/toot -X POST -H 'Content-Type: application/json' \
          -d '{"status":"hello"}'
```

Pin one exact request with `-f`, and the client's own arguments are discarded:

```
$ capcurld -S /run/cap/one -U https://api.github.com/repos/edera-dev/capcurl/ \
           -f 'GET /issues' -H 'Authorization: @/run/secrets/gh-token' &
```

Anything outside the grant is refused before it reaches the origin:

```
$ capcurl -S /run/cap/gh /../../../user/keys
capcurl: request-target rejected: must not contain '.' or '..' path segments
$ capcurl -S /run/cap/gh -X DELETE /42
capcurl: method DELETE is not permitted by this capability
$ capcurl -S /run/cap/gh -H 'Authorization: Bearer mine' /42
capcurl: client may not set header Authorization
```

Endpoint paths are `AF_UNIX` socket paths, so they have to fit in `sun_path`.

## What a grant constrains

| | |
|---|---|
| Base URI | With a trailing slash it is a prefix, and the client names what is beneath it. Without one it is that single resource. Either way it is anchored at a segment boundary, so a capability for `/capcurl` never reaches `/capcurl-evil`. |
| Methods | `GET,HEAD` by default. |
| Injected headers | Applied after the client's, so a client cannot displace them. Any `@path` word is replaced with that file's contents. |
| Client headers | `none`, `safe`, or an explicit allow-list. |
| Fixed request | One pinned method and target; the client's are discarded. |
| Body limits | In both directions. |

Redirects aren't followed. A `3xx` comes back to the client as data, because a
capability is bound to a URI and a redirect is the origin proposing a different
one.

## Cross-zone

capcurl has no transport of its own. It uses `capsudo-transport` as-is, so a
descriptor can cross an Edera zone boundary: the multiplexing transport
fabricates it locally and pumps the bytes over IDM, and neither side can tell.

Nothing needed forking. The mint handshake fits capsudo's existing field types,
so the `mux` work keeps paying off in both repositories.

Every end-to-end test in `capcurl-core` runs twice, once over a real
`SCM_RIGHTS` Unix socket and once over the multiplexer, and expects the same
results from both.

## Workspace layout

| Crate | Role |
|-------|------|
| `capcurl-grant` | What an endpoint may reach: base URI, methods, header policy, target normalization. No I/O. |
| `capcurl-http` | Strict HTTP/1.1 request parsing and response framing. No I/O. |
| `capcurl-core` | Mint handshake, daemon session logic, the origin leg. |
| `capcurld` | Daemon binary. |
| `capcurl` | Client binary. |

`examples/mint.py` is a complete client in one file, for driving a capability
from something other than Rust.
