# h3-quinn: send framed writes through Quinn chunk APIs

Ferrum carries a vendored copy of `h3-quinn` 0.0.10 so H3 framed writes use
Quinn's `write_all_chunks` path instead of repeatedly polling `poll_write` for
each contiguous `Buf` segment.

## Why

The upstream adapter receives a `WriteBuf` containing the encoded H3 frame
header followed by the frame payload. For response DATA frames, upstream loops
over `Buf::chunk()` and calls Quinn's `poll_write` once for the small header and
again for the payload. Under medium and large H3 responses this creates extra
send-side lock/poll work on the hot path.

Ferrum converts the framed write into a small list of `Bytes` chunks and passes
that list to Quinn's chunk-oriented send API. The encoded frame header is copied
into a tiny `Bytes`; payloads already backed by `Bytes` stay zero-copy through
`Buf::copy_to_bytes`.

## Retirement

Remove this patch when upstream `h3-quinn` exposes the same chunked write path,
or when Ferrum benchmark data shows this experiment does not improve H3 RPS or
tail latency enough to justify carrying it.
