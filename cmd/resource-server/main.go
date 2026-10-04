// Command resource-server is the demo protected service behind usher's
// gateway (RI-05, ADR-0013). It re-validates tokens itself against the
// published JWKS (RS-18): it imports pkg/tokenvalidator and nothing
// under internal/, so it validates exactly as an outside consumer would
// — the same way task-api or any other resource server behind the
// gateway eventually would. check-boundaries.sh enforces that this
// binary never imports internal/.
//
// Configuration is read directly from the environment (this binary has
// no internal/config to route through — that package is itself under
// internal/), fails closed on anything missing, and is deliberately
// small: RESOURCE_SERVER_ADDR, _JWKS_URL, _ISSUER, _AUDIENCE and
// _TRUSTED_PROXY_CIDRS are the whole surface.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/JonasBorgesLM/moat/realip"
	"github.com/JonasBorgesLM/usher/pkg/tokenvalidator"
)

// config is every setting this binary reads from the environment.
type config struct {
	addr           string
	jwksURL        string
	issuer         string
	audience       string
	trustedProxies []string
}

// loadConfig fails closed on anything missing — the same RNF-05 spirit
// internal/config.Load applies to usher itself, even though this binary
// is not bound by that requirement directly (it cannot import the
// package that states it).
func loadConfig() (config, error) {
	addr, ok := os.LookupEnv("RESOURCE_SERVER_ADDR")
	if !ok || addr == "" {
		addr = ":8081"
	}

	jwksURL, ok := os.LookupEnv("RESOURCE_SERVER_JWKS_URL")
	if !ok || jwksURL == "" {
		return config{}, errors.New("resource-server: RESOURCE_SERVER_JWKS_URL is required and was not set")
	}

	issuer, ok := os.LookupEnv("RESOURCE_SERVER_ISSUER")
	if !ok || issuer == "" {
		return config{}, errors.New("resource-server: RESOURCE_SERVER_ISSUER is required and was not set")
	}

	audience, ok := os.LookupEnv("RESOURCE_SERVER_AUDIENCE")
	if !ok || audience == "" {
		return config{}, errors.New("resource-server: RESOURCE_SERVER_AUDIENCE is required and was not set")
	}

	rawCIDRs, ok := os.LookupEnv("RESOURCE_SERVER_TRUSTED_PROXY_CIDRS")
	if !ok || rawCIDRs == "" {
		return config{}, errors.New("resource-server: RESOURCE_SERVER_TRUSTED_PROXY_CIDRS is required and was not set -- ADR-0010 requires declaring the gateway's own address explicitly, never a default")
	}
	var trusted []string
	for part := range strings.SplitSeq(rawCIDRs, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			trusted = append(trusted, trimmed)
		}
	}

	return config{addr: addr, jwksURL: jwksURL, issuer: issuer, audience: audience, trustedProxies: trusted}, nil
}

// The JWKS client's own bounds — RS-09's rate-limited refetch, applied
// exactly as pkg/tokenvalidator.NewJWKSSource's own doc comment
// describes, and a clock skew allowance consistent with
// internal/config's own default for usher itself.
const (
	jwksRefetchLimit  = 5
	jwksRefetchWindow = time.Minute
	jwksHTTPTimeout   = 5 * time.Second
	clockSkew         = 30 * time.Second

	shutdownTimeout = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "resource-server:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	logger := newProductionLogger(os.Stdout)

	extractor, err := realip.New(cfg.trustedProxies)
	if err != nil {
		return fmt.Errorf("resource-server: build realip extractor: %w", err)
	}

	jwksSource := tokenvalidator.NewJWKSSource(cfg.jwksURL, &http.Client{Timeout: jwksHTTPTimeout}, jwksRefetchLimit, jwksRefetchWindow)
	validator, err := tokenvalidator.New(
		jwksSource,
		[]tokenvalidator.Algorithm{tokenvalidator.RS256, tokenvalidator.ES256},
		tokenvalidator.WithIssuer(cfg.issuer),
		tokenvalidator.WithClockSkew(clockSkew),
	)
	if err != nil {
		return fmt.Errorf("resource-server: build validator: %w", err)
	}

	srv := &http.Server{
		Handler:           newRouter(validator, cfg.audience, extractor, logger),
		ReadHeaderTimeout: 5 * time.Second, // RS-21's own four, mirrored from cmd/usher/serve.go
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", cfg.addr)
	if err != nil {
		return fmt.Errorf("resource-server: listen on %s: %w", cfg.addr, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("resource-server: shutdown: %w", err)
	}
	return <-serveErr
}

// newProductionLogger mirrors cmd/usher/log.go's own function exactly —
// JSON records correlated by request id (requestIDHandler, server.go) —
// duplicated because this binary cannot import cmd/usher.
func newProductionLogger(w io.Writer) *slog.Logger {
	return slog.New(&requestIDHandler{next: slog.NewJSONHandler(w, nil)})
}
