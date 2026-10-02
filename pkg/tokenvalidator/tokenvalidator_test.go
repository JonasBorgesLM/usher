package tokenvalidator

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// fatalHelper is the slice of *testing.T and *testing.F this file's shared
// helpers need. *testing.F does not implement testing.TB (fuzz setup code
// may only use a handful of its methods before F.Fuzz is called), so a
// structural interface naming only Helper and Fatalf is what lets
// FuzzParseToken's own setup reuse the same signing helpers every other
// test in this file uses.
type fatalHelper interface {
	Helper()
	Fatalf(format string, args ...any)
}

const (
	testKID      = "test-key"
	testIssuer   = "https://usher.test"
	testAudience = "https://rs.example"
	testClientID = "client-1"
)

// fakeKeySource is a small, controllable stand-in for KeySource: a map from
// kid to the (key, registered algorithm) pair a real internal/keys.Keyset
// or JWKSSource would resolve. Real JWKS parsing is proven elsewhere
// (internal/keys's own tests); this package's tests are about what
// ValidateAccessToken itself does once a key comes back.
type fakeKeySource struct {
	keys map[string]fakeRegisteredKey
}

type fakeRegisteredKey struct {
	pub crypto.PublicKey
	alg Algorithm
}

var errUnknownTestKID = errors.New("fakeKeySource: unknown kid")

func (f *fakeKeySource) Key(_ context.Context, kid string) (crypto.PublicKey, Algorithm, error) {
	k, ok := f.keys[kid]
	if !ok {
		return nil, "", errUnknownTestKID
	}
	return k.pub, k.alg, nil
}

func testRSAKeyPair(t fatalHelper) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return priv
}

// testValidatorAndKey builds a Validator whose allow-list is RS256 only,
// backed by a fakeKeySource that resolves testKID to priv's public half,
// registered as RS256 -- the shape every test below starts from.
func testValidatorAndKey(t fatalHelper) (*Validator, *rsa.PrivateKey) {
	t.Helper()
	priv := testRSAKeyPair(t)
	source := &fakeKeySource{keys: map[string]fakeRegisteredKey{
		testKID: {pub: priv.Public(), alg: RS256},
	}}
	v, err := New(source, []Algorithm{RS256}, WithIssuer(testIssuer), WithClockSkew(30*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v, priv
}

// testValidatorWithEmptyKIDAllowed is TestValidateAccessToken_MissingKIDRejected's
// own fixture: a KeySource that -- unlike the shared fakeKeySource above --
// does resolve an empty kid, simulating a permissive or buggy KeySource
// implementation. This isolates ValidateAccessToken's own "every JWT
// carries kid" check from the unrelated case where a well-behaved source
// would have failed the lookup anyway.
func testValidatorWithEmptyKIDAllowed(t fatalHelper) (*Validator, *rsa.PrivateKey) {
	t.Helper()
	priv := testRSAKeyPair(t)
	source := &fakeKeySource{keys: map[string]fakeRegisteredKey{
		testKID: {pub: priv.Public(), alg: RS256},
		"":      {pub: priv.Public(), alg: RS256},
	}}
	v, err := New(source, []Algorithm{RS256}, WithIssuer(testIssuer), WithClockSkew(30*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v, priv
}

// testAccessClaims mirrors cmd/usher/token.go's own accessTokenClaims
// shape -- duplicated rather than imported, since pkg/ may not import
// internal/ (ADR-0001) and this package is the one that would be
// extracted first if it ever is (ADR-0009's whole premise).
type testAccessClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	Scope     string   `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JTI       string   `json:"jti"`
}

func validAccessClaims(now time.Time) testAccessClaims {
	return testAccessClaims{
		Issuer: testIssuer, Subject: "alice", Audience: []string{testAudience},
		ClientID: testClientID, Scope: "openid profile",
		ExpiresAt: now.Add(5 * time.Minute).Unix(), NotBefore: now.Unix(), IssuedAt: now.Unix(),
		JTI: "jti-1",
	}
}

// signRaw builds a compact JWS over claims, with kid/typ set on the
// protected header when non-empty -- the one place every forged-token test
// below controls exactly what a real signer would never let it control at
// once (its own kid, typ and algorithm, independently of each other).
func signRaw(t fatalHelper, alg jwa.SignatureAlgorithm, key any, kid, typ string, claims any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if kid != "" {
		if setErr := hdrs.Set(jws.KeyIDKey, kid); setErr != nil {
			t.Fatalf("set kid: %v", setErr)
		}
	}
	if typ != "" {
		if setErr := hdrs.Set(jws.TypeKey, typ); setErr != nil {
			t.Fatalf("set typ: %v", setErr)
		}
	}
	signed, err := jws.Sign(payload, jws.WithKey(alg, key, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign: %v", err)
	}
	return string(signed)
}

// signNone builds a compact JWS with alg: none -- jws.WithKey refuses this
// algorithm outright (by design, "we do not allow using none by
// accident"), so forging this one shape requires jws's own escape hatch.
func signNone(t fatalHelper, kid, typ string, claims any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	hdrs := jws.NewHeaders()
	if kid != "" {
		if setErr := hdrs.Set(jws.KeyIDKey, kid); setErr != nil {
			t.Fatalf("set kid: %v", setErr)
		}
	}
	if typ != "" {
		if setErr := hdrs.Set(jws.TypeKey, typ); setErr != nil {
			t.Fatalf("set typ: %v", setErr)
		}
	}
	signed, err := jws.Sign(payload, jws.WithInsecureNoSignature(jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		t.Fatalf("jws.Sign (none): %v", err)
	}
	return string(signed)
}

func TestValidateAccessToken_GoldenPath(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	now := time.Now()
	raw := signRaw(t, jwa.RS256(), priv, testKID, "at+jwt", validAccessClaims(now))

	claims, err := v.ValidateAccessToken(context.Background(), raw, testAudience)
	if err != nil {
		t.Fatalf("ValidateAccessToken: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "alice")
	}
	if claims.ClientID != testClientID {
		t.Errorf("ClientID = %q, want %q", claims.ClientID, testClientID)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != testAudience {
		t.Errorf("Audience = %v, want [%s]", claims.Audience, testAudience)
	}
	if claims.JTI != "jti-1" {
		t.Errorf("JTI = %q, want %q", claims.JTI, "jti-1")
	}
	if len(claims.Scope) != 2 || claims.Scope[0] != "openid" || claims.Scope[1] != "profile" {
		t.Errorf("Scope = %v, want [openid profile]", claims.Scope)
	}
}

// TestValidateAccessToken_AlgNoneRejected is RS-06/T-05: alg: none must
// never be accepted, regardless of kid or claims.
//
// No negative control was possible against this validator's own code:
// letting the token's own header algorithm override the registered one
// (the natural "what if we got RS-06 backwards" mutation) still left this
// test passing, because jws.WithKey refuses to construct a "none"
// verifier at all -- a second, independent layer underneath this
// function, not a consequence of anything it does. That refusal is tested
// by jwx itself, not usefully re-provable by mutating this file; this
// test instead stands as the direct assertion the issue's own done-when
// asks for.
func TestValidateAccessToken_AlgNoneRejected(t *testing.T) {
	v, _ := testValidatorAndKey(t)
	raw := signNone(t, testKID, "at+jwt", validAccessClaims(time.Now()))

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("an alg:none token was accepted")
	}
}

// TestValidateAccessToken_RS256ToHS256KeyConfusionRejected is RS-06/T-05's
// other named attack: the classic downgrade where an attacker HMAC-signs
// a forged token using the RSA *public* key's own bytes as the HS256
// secret -- anyone holding the published public key can compute this
// signature.
//
// Negative control: trusting the header's own alg alone (as the alg:none
// test's own mutation did) was not enough to reproduce this attack --
// jws.WithKey's own key/algorithm type check refused HS256 together with
// an *rsa.PublicKey regardless of who chose HS256, which the real
// vulnerability (treating the public key's raw bytes as an opaque HMAC
// secret) requires bypassing too. With a second change layered on top --
// marshaling the RSA public key to raw bytes and passing those as the
// key whenever the header's own alg was symmetric, reproducing what a
// library with no key/alg type check would do -- this test failed, the
// forged HS256 token verified successfully against the public key's own
// bytes. Verified by hand, restored before committing.
func TestValidateAccessToken_RS256ToHS256KeyConfusionRejected(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	pubDER, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	raw := signRaw(t, jwa.HS256(), pubDER, testKID, "at+jwt", validAccessClaims(time.Now()))

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("an RS256-key-as-HS256-secret forged token was accepted")
	}
}

// TestValidateAccessToken_MissingKIDRejected is RS-09: every JWT carries
// kid, checked by ValidateAccessToken itself -- deliberately using a
// fixture whose KeySource *would* resolve an empty kid, so this proves
// the function's own check, not an incidental lookup failure.
//
// Negative control: with the `!ok || kid == ""` check removed from
// ValidateAccessToken, this test failed -- the kid-less token was
// accepted, since testValidatorWithEmptyKIDAllowed's source resolves ""
// to a real key. Verified by hand, restored before committing.
func TestValidateAccessToken_MissingKIDRejected(t *testing.T) {
	v, priv := testValidatorWithEmptyKIDAllowed(t)
	raw := signRaw(t, jwa.RS256(), priv, "", "at+jwt", validAccessClaims(time.Now()))

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("a token with no kid was accepted, even though the key source would have resolved the empty string")
	}
}

// TestValidateAccessToken_WrongTypeAloneRejected is RS-08's typ half,
// isolated: aud is already correct, so only the typ check can be doing
// the rejecting.
//
// Negative control: with the `typ != "at+jwt"` check removed from
// ValidateAccessToken, this test failed -- an id_token-shaped token with
// an otherwise-correct audience was accepted as an access token. Verified
// by hand, restored before committing.
func TestValidateAccessToken_WrongTypeAloneRejected(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	claims := validAccessClaims(time.Now()) // Audience is already testAudience.
	raw := signRaw(t, jwa.RS256(), priv, testKID, "id_token", claims)

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("a token with typ=id_token (but a correct aud) was accepted as an access token")
	}
}

// TestValidateAccessToken_WrongAudienceAloneRejected is RS-08/RS-19's aud
// half, isolated: typ is already correct (at+jwt), so only the audience
// check can be doing the rejecting -- an ID token's own aud shape
// (= the client, not a resource server) presented with the right typ.
//
// Negative control: with the `jwt.WithAudience(wantAudience)` option
// removed from the jwt.Parse call, this test failed -- a token whose aud
// was only the client_id (never the requested resource server) was
// accepted. Verified by hand, restored before committing.
func TestValidateAccessToken_WrongAudienceAloneRejected(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	claims := validAccessClaims(time.Now())
	claims.Audience = []string{testClientID} // ID-token-shaped aud.
	raw := signRaw(t, jwa.RS256(), priv, testKID, "at+jwt", claims)

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("a token whose aud never names the requested resource server was accepted")
	}
}

// TestValidateAccessToken_AlgorithmNotInAllowListRejected is RS-06's other
// half: the allow-list is fixed AT CONSTRUCTION, so a kid correctly and
// consistently registered under ES256, with a genuinely valid ES256
// signature, is still refused by a Validator built with allowed =
// []Algorithm{RS256} only.
//
// Negative control: with the `!slices.Contains(v.allowed, registeredAlg)`
// check removed from ValidateAccessToken, this test failed -- the
// correctly self-consistent ES256 token was accepted despite the
// construction-time allow-list naming only RS256. Verified by hand,
// restored before committing.
func TestValidateAccessToken_AlgorithmNotInAllowListRejected(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	source := &fakeKeySource{keys: map[string]fakeRegisteredKey{
		testKID: {pub: ecKey.Public(), alg: ES256},
	}}
	v, err := New(source, []Algorithm{RS256}, WithIssuer(testIssuer), WithClockSkew(30*time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	raw := signRaw(t, jwa.ES256(), ecKey, testKID, "at+jwt", validAccessClaims(time.Now()))

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("an ES256 token, correctly registered and signed, was accepted by a validator whose allow-list names only RS256")
	}
}

// testAccessClaimsNoJTI is validAccessClaims's shape with jti omitted
// entirely, for TestValidateAccessToken_MissingJTIRejected.
type testAccessClaimsNoJTI struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ClientID  string   `json:"client_id"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
}

// TestValidateAccessToken_MissingJTIRejected is RS-07: jti must be
// present, not merely valid when present.
//
// Negative control: with the `jwt.WithRequiredClaim(jwt.JwtIDKey)` option
// removed from the jwt.Parse call, this test failed -- a token with no
// jti claim at all was accepted. Verified by hand, restored before
// committing.
func TestValidateAccessToken_MissingJTIRejected(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	now := time.Now()
	claims := testAccessClaimsNoJTI{
		Issuer: testIssuer, Subject: "alice", Audience: []string{testAudience}, ClientID: testClientID,
		ExpiresAt: now.Add(5 * time.Minute).Unix(), NotBefore: now.Unix(), IssuedAt: now.Unix(),
	}
	raw := signRaw(t, jwa.RS256(), priv, testKID, "at+jwt", claims)

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("a token with no jti claim was accepted")
	}
}

// TestValidateAccessToken_ClockSkewAllowsSmallDrift is RS-07: clock skew
// is configurable and actually applied, not merely documented -- a token
// that expired 10s ago still validates under a 30s skew allowance.
//
// Negative control: with the `jwt.WithAcceptableSkew(v.cfg.clockSkew)`
// option removed from the jwt.Parse call, this test failed -- the token,
// expired by only 10 seconds, was rejected as expired. Verified by hand,
// restored before committing.
func TestValidateAccessToken_ClockSkewAllowsSmallDrift(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	now := time.Now()
	claims := validAccessClaims(now)
	claims.ExpiresAt = now.Add(-10 * time.Second).Unix()
	raw := signRaw(t, jwa.RS256(), priv, testKID, "at+jwt", claims)

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err != nil {
		t.Fatalf("a token 10s past exp, within a 30s clock skew, was rejected: %v", err)
	}
}

// TestValidateAccessToken_ExpiredBeyondSkewRejected is the clock-skew
// test's own control case: well past exp, even with skew applied, is
// still rejected -- skew is a bounded allowance, not a disabled check.
func TestValidateAccessToken_ExpiredBeyondSkewRejected(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	now := time.Now()
	claims := validAccessClaims(now)
	claims.ExpiresAt = now.Add(-time.Hour).Unix()
	raw := signRaw(t, jwa.RS256(), priv, testKID, "at+jwt", claims)

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("a token expired by an hour, far beyond the 30s clock skew, was accepted")
	}
}

func TestValidateAccessToken_UnknownKIDRejected(t *testing.T) {
	v, priv := testValidatorAndKey(t)
	raw := signRaw(t, jwa.RS256(), priv, "never-registered", "at+jwt", validAccessClaims(time.Now()))

	if _, err := v.ValidateAccessToken(context.Background(), raw, testAudience); err == nil {
		t.Fatal("a token with an unknown kid was accepted")
	}
}

// FuzzParseToken is the issue's own done-when: no malformed input produces
// an accepted token. The seed corpus deliberately avoids including a
// pristine, genuinely valid token (which this property would itself
// reject as a false alarm) -- near-miss shapes derived from one instead.
func FuzzParseToken(f *testing.F) {
	v, priv := testValidatorAndKey(f)

	valid := signRaw(f, jwa.RS256(), priv, testKID, "at+jwt", validAccessClaims(time.Now()))

	// Flipping a bit well inside the signature, rather than its very last
	// character: base64url's final character in a group carries a couple
	// of "don't care" low bits, so changing only that one character can
	// decode to the exact same bytes and leave a valid signature valid.
	// Found by this fuzz target's own seed corpus failing on first run.
	corruptedBytes := []byte(valid)
	corruptedBytes[len(corruptedBytes)-20] ^= 0x01
	corrupted := string(corruptedBytes)

	seeds := []string{
		"",
		"not a jwt",
		"a.b.c",
		"..",
		"eyJhbGciOiJub25lIn0.e30.",
		corrupted,
		valid[:len(valid)/2], // truncated mid-signature
		valid[:len(valid)/3], // truncated mid-payload
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		claims, err := v.ValidateAccessToken(context.Background(), raw, testAudience)
		if err == nil {
			t.Fatalf("fuzz input accepted as a valid access token: %q -> %+v", raw, claims)
		}
	})
}
