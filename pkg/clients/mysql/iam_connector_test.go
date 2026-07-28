package mysql

import (
	"context"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	"github.com/pkg/errors"

	"github.com/crossplane-contrib/provider-sql/pkg/clients/xsql"

	xpv1 "github.com/crossplane/crossplane-runtime/v2/apis/common/v1"
)

// fakeMinter returns tokens[calls % len(tokens)], counting invocations so a
// test can assert one mint per physical connection and observe rotation.
type fakeMinter struct {
	calls  int
	tokens []string
	err    error
}

func (f *fakeMinter) Mint(_ context.Context) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	tok := f.tokens[f.calls%len(f.tokens)]
	f.calls++
	return tok, nil
}

// stubConn / stubConnector stand in for the go-sql-driver connector so the
// iamConnector can be exercised without opening a real network connection.
type stubConn struct{}

func (stubConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (stubConn) Close() error                        { return nil }
func (stubConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

type stubConnector struct{}

func (stubConnector) Connect(context.Context) (driver.Conn, error) { return stubConn{}, nil }
func (stubConnector) Driver() driver.Driver                        { return mysqldriver.MySQLDriver{} }

func iamCreds() map[string][]byte {
	return map[string][]byte{
		xpv1.ResourceCredentialsSecretUserKey:     []byte("iam_admin"),
		xpv1.ResourceCredentialsSecretEndpointKey: []byte("cluster.example.rds.amazonaws.com"),
		xpv1.ResourceCredentialsSecretPortKey:     []byte("3306"),
	}
}

// The token is a ~15-min credential; the pool must be keyed by something
// stable so rotation reuses the same pool instead of leaking a new one per
// mint. Two clients minting different tokens must share one *sql.DB.
func TestNewWithMinter_PoolKeyExcludesToken(t *testing.T) {
	resetPoolCacheForTest()
	tlsMode := "skip-verify"
	ct := true

	tokenA := "token-AAAAAAAAAAAAAAAA"
	tokenB := "token-BBBBBBBBBBBBBBBB"
	NewWithMinter(iamCreds(), &tlsMode, nil, nil, &ct, &fakeMinter{tokens: []string{tokenA}})
	NewWithMinter(iamCreds(), &tlsMode, nil, nil, &ct, &fakeMinter{tokens: []string{tokenB}})

	if len(poolCache) != 1 {
		t.Fatalf("expected a single shared pool across token rotation, got %d entries", len(poolCache))
	}
	for key := range poolCache {
		if strings.Contains(key, tokenA) || strings.Contains(key, tokenB) {
			t.Errorf("pool key must not contain the token; key = %q", key)
		}
	}
}

// A fresh token must be minted for every physical connection, and that token
// must reach the driver as the (cleartext-enabled) password.
func TestIAMConnector_MintsFreshTokenPerConnection(t *testing.T) {
	tlsMode := "skip-verify"
	ct := true
	dsn := dsnWithTimeout("iam_admin", "", "cluster.example.rds.amazonaws.com", "3306", tlsMode, nil, 0, &ct)

	minter := &fakeMinter{tokens: []string{"tok-1", "tok-2", "tok-3"}}
	var captured []*mysqldriver.Config
	c := &iamConnector{
		dsn:    dsn,
		minter: minter,
		newInner: func(cfg *mysqldriver.Config) (driver.Connector, error) {
			captured = append(captured, cfg)
			return stubConnector{}, nil
		},
	}

	for i := 0; i < 3; i++ {
		if _, err := c.Connect(context.Background()); err != nil {
			t.Fatalf("Connect() call %d: unexpected error: %v", i, err)
		}
	}

	if minter.calls != 3 {
		t.Errorf("expected Mint called once per connection (3), got %d", minter.calls)
	}
	want := []string{"tok-1", "tok-2", "tok-3"}
	for i, cfg := range captured {
		if cfg.Passwd != want[i] {
			t.Errorf("connection %d: password = %q, want fresh token %q", i, cfg.Passwd, want[i])
		}
		if !cfg.AllowCleartextPasswords {
			t.Errorf("connection %d: AllowCleartextPasswords must be true for RDS IAM auth", i)
		}
		if cfg.User != "iam_admin" {
			t.Errorf("connection %d: User = %q, want iam_admin", i, cfg.User)
		}
		if cfg.Addr != "cluster.example.rds.amazonaws.com:3306" {
			t.Errorf("connection %d: Addr = %q, want host:port", i, cfg.Addr)
		}
	}
}

// Exercise the real NewWithMinter -> getOrOpenPoolConnector -> Connect -> Mint
// path (not the hand-built connector): a query forces the pool to open a
// physical connection, which must invoke the minter before dialing. The dial
// then fails (unreachable addr) — that's fine; we only assert the wiring
// reached the minter.
func TestNewWithMinter_InvokesMinterOnConnect(t *testing.T) {
	resetPoolCacheForTest()
	tlsMode := "skip-verify"
	ct := true
	creds := map[string][]byte{
		xpv1.ResourceCredentialsSecretUserKey:     []byte("iam_admin"),
		xpv1.ResourceCredentialsSecretEndpointKey: []byte("127.0.0.1"),
		xpv1.ResourceCredentialsSecretPortKey:     []byte("1"), // refuses fast
	}
	minter := &fakeMinter{tokens: []string{"tok"}}
	poolCfg := &ConnectionPoolConfig{DialTimeout: 2 * time.Second}
	db := NewWithMinter(creds, &tlsMode, nil, poolCfg, &ct, minter)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Expected to fail at dial; we only care that the minter was consulted.
	_ = db.Exec(ctx, xsql.Query{String: "SELECT 1"})

	if minter.calls == 0 {
		t.Error("NewWithMinter pool did not invoke the minter when opening a connection")
	}
}

// A mint failure surfaces as a connect error and never reaches the driver.
func TestIAMConnector_MintErrorPropagates(t *testing.T) {
	inner := false
	c := &iamConnector{
		dsn:    dsnWithTimeout("u", "", "h", "3306", "skip-verify", nil, 0, boolPtr(true)),
		minter: &fakeMinter{err: errors.New("assume-role denied")},
		newInner: func(*mysqldriver.Config) (driver.Connector, error) {
			inner = true
			return stubConnector{}, nil
		},
	}
	_, err := c.Connect(context.Background())
	if err == nil {
		t.Fatal("expected an error when minting fails")
	}
	if !strings.Contains(err.Error(), "assume-role denied") {
		t.Errorf("error should wrap the mint failure, got %v", err)
	}
	if inner {
		t.Error("driver connector must not be built when minting fails")
	}
}
