package identity

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are Argon2id's tunable cost parameters (ADR-0005). Every hash
// carries its own Params inside its PHC string, so changing DefaultParams
// never invalidates an existing record — it only makes that record due for
// a rehash on its next successful login (NeedsRehash).
type Params struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams is this project's current Argon2id calibration. RS-33's
// memory ceiling (issue #15) is checked against Memory at startup; it is not
// decided here.
var DefaultParams = Params{
	Memory:      64 * 1024, // 64 MiB
	Iterations:  3,
	Parallelism: 4,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword hashes password under params and returns it as a PHC string
// (RS-13): $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>, both salt and
// hash base64 without padding.
func HashPassword(password string, params Params) (string, error) {
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("identity: generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword reports whether password matches encoded. Comparison is
// constant-time (crypto/subtle.ConstantTimeCompare) — never == or
// bytes.Equal, which forbidigo's RS-15 rule already refuses project-wide.
func VerifyPassword(password, encoded string) (bool, error) {
	params, salt, hash, err := decodePHC(encoded)
	if err != nil {
		return false, err
	}
	candidate := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(hash))) // #nosec G115 -- hash came from decodePHC, already bounded
	return subtle.ConstantTimeCompare(candidate, hash) == 1, nil
}

// NeedsRehash reports whether encoded's parameters are weaker than current
// in any dimension — ADR-0005's transparent rehash-on-login. There is no
// bulk migration path: a record stays at its old parameters until it next
// authenticates successfully.
func NeedsRehash(encoded string, current Params) (bool, error) {
	params, _, _, err := decodePHC(encoded)
	if err != nil {
		return false, err
	}
	return params.Memory < current.Memory ||
		params.Iterations < current.Iterations ||
		params.Parallelism < current.Parallelism ||
		params.SaltLength < current.SaltLength ||
		params.KeyLength < current.KeyLength, nil
}

var (
	// ErrInvalidHash reports that encoded is not a well-formed PHC string.
	ErrInvalidHash = errors.New("identity: invalid password hash")
	// ErrUnsupportedVariant reports a PHC string for an algorithm other
	// than argon2id — this project never wrote one, but a hash reaching
	// here from anywhere else (a restored backup, a manual edit) must be
	// refused rather than misread.
	ErrUnsupportedVariant = errors.New("identity: unsupported hash variant")
	// ErrIncompatibleVersion reports an Argon2 version this build's
	// golang.org/x/crypto/argon2 does not implement.
	ErrIncompatibleVersion = errors.New("identity: incompatible argon2 version")
)

// decodePHC parses $argon2id$v=<version>$m=<mem>,t=<iter>,p=<par>$<salt>$<hash>.
func decodePHC(encoded string) (params Params, salt, hash []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrUnsupportedVariant
	}

	var version int
	if _, scanErr := fmt.Sscanf(parts[2], "v=%d", &version); scanErr != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: version segment %q: %w", ErrInvalidHash, parts[2], scanErr)
	}
	if version != argon2.Version {
		return Params{}, nil, nil, ErrIncompatibleVersion
	}

	if _, scanErr := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); scanErr != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: parameter segment %q: %w", ErrInvalidHash, parts[3], scanErr)
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: salt: %w", ErrInvalidHash, err)
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: hash: %w", ErrInvalidHash, err)
	}
	// maxFieldLength bounds the decoded salt and hash: a legitimate PHC
	// string never approaches it (DefaultParams uses 16 and 32 bytes), and
	// bounding it closes the int -> uint32 conversion below against a
	// corrupted or adversarial record claiming an enormous length, not just
	// against a value that happens not to overflow today.
	const maxFieldLength = 1024
	if len(salt) > maxFieldLength || len(hash) > maxFieldLength {
		return Params{}, nil, nil, fmt.Errorf("%w: salt or hash exceeds %d bytes", ErrInvalidHash, maxFieldLength)
	}
	params.SaltLength = uint32(len(salt)) // #nosec G115 -- bounded above by maxFieldLength
	params.KeyLength = uint32(len(hash))  // #nosec G115 -- bounded above by maxFieldLength
	return params, salt, hash, nil
}
