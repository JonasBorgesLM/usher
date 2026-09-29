package config

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOSEnvironmentIsReadOnlyInConfig makes this package's own doc comment
// mechanical: os.Getenv and os.LookupEnv must never appear outside
// internal/config, or a later feature reading the environment directly gets
// a setting Load's checks never see — RF-01's client registry, RS-19's
// per-route audiences, RS-33's Argon2id memory ceiling and RNF-07's eviction
// check are all supposed to be values Load hands down, not a second os.Getenv
// call of their own.
//
// Test files are excluded: the rule is about the application reading its own
// configuration in one place, not about what a _test.go file's setup does.
//
// Negative control: run once against a scratch file under internal/oauth
// containing `_ = os.Getenv("X")` — this test failed, naming the file and
// the call, then passed again once the file was removed.
func TestOSEnvironmentIsReadOnlyInConfig(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()

	violations := 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "graphify-out", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == filepath.Join("internal", "config", "config.go") ||
			strings.HasPrefix(rel, filepath.Join("internal", "config")+string(filepath.Separator)) {
			return nil // this package is where reading the environment belongs
		}

		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := sel.X.(*ast.Ident)
			if !ok || pkgIdent.Name != "os" {
				return true
			}
			if sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv" {
				violations++
				t.Errorf("%s:%d reads the environment directly (os.%s) — only internal/config may; route it through config.Load instead",
					rel, fset.Position(n.Pos()).Line, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	if violations == 0 {
		t.Log("no environment reads found outside internal/config")
	}
}

// moduleRoot finds the directory holding go.mod by walking up from the
// current package — internal/config is two levels below it.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("moduleRoot: no go.mod found above internal/config")
		}
		dir = parent
	}
}
