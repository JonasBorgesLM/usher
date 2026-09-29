module github.com/JonasBorgesLM/usher

// 1.26.6 is a security floor inherited from moat/redisstore, not a language
// feature choice: that module reaches crypto/tls and encoding/asn1, fixed for
// GO-2026-6090 and GO-2026-5972 in 1.26.6. 1.25.13 would not do: Go orders
// versions across lines, so 1.26.5 satisfies it and has neither fix. ADR-0008.
go 1.26.6

require github.com/JonasBorgesLM/bastion v0.2.1
