package mysql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	// Importing the MySQL driver registers the "mysql" driver via its
	// init(); a named import also gives this package the Config/Connector
	// types needed for the per-connection token-minting path.
	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/crossplane-contrib/provider-sql/pkg/clients/xsql"
	"github.com/pkg/errors"

	xpv1 "github.com/crossplane/crossplane-runtime/v2/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
)

const (
	errNotSupported = "%s not supported by mysql client"

	errCleartextRequiresTLS = `allowCleartextPasswords requires tls to be "true", "skip-verify", or "custom" — "preferred" (including the unset default) permits an unencrypted fallback connection`
)

// ConnectionPoolConfig contains optional connection-pool tuning for the
// MySQL client. A nil ConnectionPoolConfig preserves go's database/sql
// defaults.
//
// The fields map directly to *sql.DB methods of the same name; see the
// Go standard library documentation for semantics.
type ConnectionPoolConfig struct {
	// MaxOpenConns bounds simultaneous in-use connections per pool.
	// 0 leaves the limit unbounded (Go default).
	MaxOpenConns int
	// MaxIdleConns bounds idle pool size. 0 uses Go's default (2).
	// Negative values disable idle connection retention entirely.
	MaxIdleConns int
	// ConnMaxLifetime caps how long a connection may be reused. 0
	// allows connections to live forever (Go default). Useful behind
	// load balancers and connection-pooling proxies that close
	// long-lived connections from their side.
	ConnMaxLifetime time.Duration
	// ConnMaxIdleTime caps how long a connection may sit idle in the
	// pool before being closed. 0 allows idle connections to live
	// forever (Go default).
	ConnMaxIdleTime time.Duration
	// DialTimeout bounds the TCP connect and TLS handshake that
	// open new connections to the database. 0 leaves the
	// go-sql-driver default (no timeout) in place — recommended to
	// override behind any proxy that can hang on connect.
	DialTimeout time.Duration
}

// poolCache holds *sql.DB instances keyed by DSN. The crossplane
// reconciler invokes mysql.New on every Connect() call, and *sql.DB
// is itself a connection pool — opening a new one per reconcile (the
// pre-cache behavior) defeats the Go documentation guarantee that
// "Open function should be called just once" (database/sql docs,
// referenced in upstream issue #110). Caching by DSN means a
// credential rotation lands a fresh pool; the now-orphaned previous
// pool eventually drops its idle connections per ConnMaxIdleTime and
// is later eligible for collection if the entry is evicted.
//
// The cache lives for the lifetime of the provider process. There is
// no explicit eviction — DSN cardinality is bounded by the number of
// distinct ProviderConfig credential rotations, which is small in
// practice.
var (
	poolCacheMu sync.Mutex
	poolCache   = map[string]*sql.DB{}
)

// getOrOpenPool returns the cached *sql.DB for the DSN, opening and
// configuring one on first use.
func getOrOpenPool(dsn string, cfg *ConnectionPoolConfig) (*sql.DB, error) {
	poolCacheMu.Lock()
	defer poolCacheMu.Unlock()
	if db, ok := poolCache[dsn]; ok {
		return db, nil
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	applyPoolConfig(db, cfg)
	poolCache[dsn] = db
	return db, nil
}

// getOrOpenPoolConnector is getOrOpenPool for a driver.Connector-backed pool
// (sql.OpenDB) rather than a DSN string (sql.Open). key must be stable across
// credential rotation so a rotating token does not create a new pool.
func getOrOpenPoolConnector(key string, cfg *ConnectionPoolConfig, connector driver.Connector) *sql.DB {
	poolCacheMu.Lock()
	defer poolCacheMu.Unlock()
	if db, ok := poolCache[key]; ok {
		return db
	}
	db := sql.OpenDB(connector)
	applyPoolConfig(db, cfg)
	poolCache[key] = db
	return db
}

// applyPoolConfig applies optional pool tuning; a nil cfg leaves Go defaults.
func applyPoolConfig(db *sql.DB, cfg *ConnectionPoolConfig) {
	if cfg == nil {
		return
	}
	if cfg.MaxOpenConns != 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns != 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}
}

// NewConnectionPoolConfig builds a ConnectionPoolConfig from plain
// values. Returns nil if every input is zero, which preserves the
// "no pool tuning" path in NewWithConfig (Go defaults apply).
// Convenience constructor for reconcilers — they unwrap the optional
// fields from ProviderConfigSpec.ConnectionPool via
// ConnectionPoolSpec.ToPoolValues.
func NewConnectionPoolConfig(maxOpen, maxIdle int, lifetime, idleTime, dialTimeout time.Duration) *ConnectionPoolConfig {
	if maxOpen == 0 && maxIdle == 0 && lifetime == 0 && idleTime == 0 && dialTimeout == 0 {
		return nil
	}
	return &ConnectionPoolConfig{
		MaxOpenConns:    maxOpen,
		MaxIdleConns:    maxIdle,
		ConnMaxLifetime: lifetime,
		ConnMaxIdleTime: idleTime,
		DialTimeout:     dialTimeout,
	}
}

// resetPoolCacheForTest is exported only for tests to ensure cache
// state is deterministic across test runs. Not part of the public API.
func resetPoolCacheForTest() {
	poolCacheMu.Lock()
	defer poolCacheMu.Unlock()
	for dsn, db := range poolCache {
		_ = db.Close()
		delete(poolCache, dsn)
	}
}

// ValidateAllowCleartextPasswords rejects allowCleartextPasswords=true
// unless tls resolves to a mode that guarantees an encrypted connection.
// "preferred" (and the unset default, which resolves to "preferred") may
// silently fall back to an unencrypted connection, which would send the
// password in cleartext over the network — defeating the point of the
// driver's opt-in safety guard. tls should be the resolved value returned
// by tls.LoadConfig, not the raw ProviderConfig field, so that tls=custom
// (resolved to a registered config name) is correctly treated as encrypted.
func ValidateAllowCleartextPasswords(tls *string, allowCleartextPasswords *bool) error {
	if allowCleartextPasswords == nil || !*allowCleartextPasswords {
		return nil
	}
	if tls == nil || *tls == "preferred" {
		return errors.New(errCleartextRequiresTLS)
	}
	return nil
}

type mySQLDB struct {
	db       *sql.DB
	openErr  error // sticky error from initial pool open, returned by Exec/Query/Scan
	dsn      string
	endpoint string
	port     string
	tls      string
}

// New returns a MySQL database client. Equivalent to NewWithConfig with
// a nil config and no cleartext-password override. Preserved for backward
// compatibility with existing callers; new code should prefer NewWithConfig.
func New(creds map[string][]byte, tls *string, binlog *bool) xsql.DB {
	return NewWithConfig(creds, tls, binlog, nil, nil)
}

// NewWithConfig returns a MySQL database client backed by a process-wide
// connection pool keyed by DSN. Multiple calls with equivalent
// credentials share a *sql.DB instance, so reconciles across resources
// amortize connection cost rather than opening a fresh TCP+TLS+MySQL
// handshake per call.
//
// A nil cfg preserves Go's database/sql default pool settings
// (unlimited open connections, 2 idle connections, no max lifetime,
// no dial timeout). Provide a ConnectionPoolConfig to bound the pool
// — see upstream issues #110, #195, #220 for the failure modes the
// defaults can cause under load.
//
// allowCleartextPasswords opts into sending the password in cleartext
// when the server requests an auth method that requires it (e.g. AWS
// RDS/Aurora's AWSAuthenticationPlugin for IAM database authentication).
// See ValidateAllowCleartextPasswords for the TLS requirement this implies.
func NewWithConfig(creds map[string][]byte, tls *string, binlog *bool, cfg *ConnectionPoolConfig, allowCleartextPasswords *bool) xsql.DB {
	endpoint := string(creds[xpv1.ResourceCredentialsSecretEndpointKey])
	port := string(creds[xpv1.ResourceCredentialsSecretPortKey])
	username := string(creds[xpv1.ResourceCredentialsSecretUserKey])
	password := string(creds[xpv1.ResourceCredentialsSecretPasswordKey])
	if tls == nil {
		defaultTLS := "preferred"
		tls = &defaultTLS
	}
	var dialTimeout time.Duration
	if cfg != nil {
		dialTimeout = cfg.DialTimeout
	}
	dsn := dsnWithTimeout(username, password, endpoint, port, *tls, binlog, dialTimeout, allowCleartextPasswords)

	db, err := getOrOpenPool(dsn, cfg)
	return mySQLDB{
		db:       db,
		openErr:  err,
		dsn:      dsn,
		endpoint: endpoint,
		port:     port,
		tls:      *tls,
	}
}

// TokenMinter produces a short-lived database password on demand — e.g. an
// AWS RDS IAM authentication token. It is invoked once per new physical
// connection, so an expired token never blocks a fresh connect and the token
// is never persisted in a DSN, a pool key, or a Kubernetes Secret.
type TokenMinter interface {
	Mint(ctx context.Context) (string, error)
}

// iamConnector is a database/sql/driver.Connector that mints a fresh password
// for every physical connection via minter, then delegates to the
// go-sql-driver connector built from the password-less base DSN.
type iamConnector struct {
	dsn    string // password-less DSN; carries host, tls, allowCleartextPasswords, timeout
	minter TokenMinter
	// newInner builds the delegate connector for a fully-resolved config.
	// Overridable in tests to observe the config at the driver boundary
	// without opening a real connection.
	newInner func(*mysqldriver.Config) (driver.Connector, error)
}

func newMySQLConnector(cfg *mysqldriver.Config) (driver.Connector, error) {
	return mysqldriver.NewConnector(cfg)
}

// Connect mints a fresh token and opens one physical connection with it.
func (c *iamConnector) Connect(ctx context.Context) (driver.Conn, error) {
	token, err := c.minter.Mint(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "cannot mint database auth token")
	}
	cfg, err := mysqldriver.ParseDSN(c.dsn)
	if err != nil {
		return nil, errors.Wrap(err, "cannot parse base DSN")
	}
	cfg.Passwd = token
	inner, err := c.newInner(cfg)
	if err != nil {
		return nil, err
	}
	return inner.Connect(ctx)
}

// Driver returns the underlying MySQL driver.
func (c *iamConnector) Driver() driver.Driver { return mysqldriver.MySQLDriver{} }

// NewWithMinter returns a MySQL client whose password is minted fresh for
// every physical connection by minter, rather than read from creds. This is
// the path for AWS RDS IAM database authentication: the password is a
// ~15-minute token, so minting per-connect means an expired token never
// blocks a new connection. The token never enters the DSN, the pool key, or
// any Secret, so the pool is keyed by a password-less DSN and is NOT churned
// when the token rotates — unlike the static-password path, where each
// rotation lands a fresh pool.
//
// allowCleartextPasswords must be true for RDS IAM auth (the server requests
// the mysql_clear_password plugin); ValidateAllowCleartextPasswords still
// governs the TLS requirement.
func NewWithMinter(creds map[string][]byte, tls *string, binlog *bool, cfg *ConnectionPoolConfig, allowCleartextPasswords *bool, minter TokenMinter) xsql.DB {
	endpoint := string(creds[xpv1.ResourceCredentialsSecretEndpointKey])
	port := string(creds[xpv1.ResourceCredentialsSecretPortKey])
	username := string(creds[xpv1.ResourceCredentialsSecretUserKey])
	if tls == nil {
		defaultTLS := "preferred"
		tls = &defaultTLS
	}
	var dialTimeout time.Duration
	if cfg != nil {
		dialTimeout = cfg.DialTimeout
	}
	// Password-less DSN: stable across token rotation. Serves as both the
	// connector's base config and the pool key.
	baseDSN := dsnWithTimeout(username, "", endpoint, port, *tls, binlog, dialTimeout, allowCleartextPasswords)
	key := "iam:" + baseDSN

	db := getOrOpenPoolConnector(key, cfg, &iamConnector{
		dsn:      baseDSN,
		minter:   minter,
		newInner: newMySQLConnector,
	})
	return mySQLDB{
		db:       db,
		dsn:      key,
		endpoint: endpoint,
		port:     port,
		tls:      *tls,
	}
}

// DSN returns the DSN URL with no dial timeout and no cleartext-password
// override. Preserved for backward compatibility; new code should call
// DSNWithDialTimeout or, for full control, dsnWithTimeout directly.
func DSN(username, password, endpoint, port, tls string, binlog *bool) string {
	return dsnWithTimeout(username, password, endpoint, port, tls, binlog, 0, nil)
}

// DSNWithDialTimeout returns the DSN URL with an optional dial timeout
// appended as the go-sql-driver `timeout` parameter. A zero or negative
// dialTimeout omits the parameter, leaving the driver default (no
// timeout) in place.
func DSNWithDialTimeout(username, password, endpoint, port, tls string, binlog *bool, dialTimeout time.Duration) string {
	return dsnWithTimeout(username, password, endpoint, port, tls, binlog, dialTimeout, nil)
}

func dsnWithTimeout(username, password, endpoint, port, tls string, binlog *bool, dialTimeout time.Duration, allowCleartextPasswords *bool) string {
	var extra []string
	if binlog != nil {
		extra = append(extra, "sql_log_bin="+strconv.FormatBool(*binlog))
	}
	if dialTimeout > 0 {
		// go-sql-driver accepts Go duration strings (e.g. "10s", "1m")
		// and turns them into the underlying net.Dialer Timeout.
		extra = append(extra, "timeout="+dialTimeout.String())
	}
	if allowCleartextPasswords != nil {
		extra = append(extra, "allowCleartextPasswords="+strconv.FormatBool(*allowCleartextPasswords))
	}
	base := fmt.Sprintf("%s:%s@tcp(%s:%s)/?tls=%s",
		username, password, endpoint, port, tls)
	for _, p := range extra {
		base += "&" + p
	}
	return base
}

// ExecTx is unsupported in MySQL.
func (c mySQLDB) ExecTx(ctx context.Context, ql []xsql.Query) error {
	return errors.Errorf(errNotSupported, "transactions")
}

// Exec the supplied query.
func (c mySQLDB) Exec(ctx context.Context, q xsql.Query) error {
	if c.openErr != nil {
		return c.openErr
	}
	_, err := c.db.ExecContext(ctx, q.String, q.Parameters...)
	return err
}

// Query the supplied query.
func (c mySQLDB) Query(ctx context.Context, q xsql.Query) (*sql.Rows, error) {
	if c.openErr != nil {
		return nil, c.openErr
	}
	return c.db.QueryContext(ctx, q.String, q.Parameters...)
}

// Scan the results of the supplied query into the supplied destination.
func (c mySQLDB) Scan(ctx context.Context, q xsql.Query, dest ...interface{}) error {
	if c.openErr != nil {
		return c.openErr
	}
	return c.db.QueryRowContext(ctx, q.String, q.Parameters...).Scan(dest...)
}

// GetConnectionDetails returns the connection details for a user of this DB
func (c mySQLDB) GetConnectionDetails(username, password string) managed.ConnectionDetails {
	return managed.ConnectionDetails{
		xpv1.ResourceCredentialsSecretUserKey:     []byte(username),
		xpv1.ResourceCredentialsSecretPasswordKey: []byte(password),
		xpv1.ResourceCredentialsSecretEndpointKey: []byte(c.endpoint),
		xpv1.ResourceCredentialsSecretPortKey:     []byte(c.port),
	}
}

// GetServerVersion is not supported by the MySQL client (only used by PostgreSQL).
func (c mySQLDB) GetServerVersion(ctx context.Context) (int, error) {
	// This method should never be called for MySQL clients
	// but is implemented to satisfy the xsql.DB interface
	return 0, nil
}

// QuoteIdentifier for MySQL queries
func QuoteIdentifier(id string) string {
	return "`" + strings.ReplaceAll(id, "`", "``") + "`"
}

// QuoteValue for MySQL queries
func QuoteValue(id string) string {
	return "'" + strings.ReplaceAll(id, "'", "''") + "'"
}

// SplitUserHost splits a MySQL user by name and host
func SplitUserHost(user string) (username, host string) {
	username = user
	host = "%"
	if strings.Contains(user, "@") {
		parts := strings.SplitN(user, "@", 2)
		username = parts[0]
		host = parts[1]
	}
	return username, host
}

// ExecQuery declares the query to execute and its error value if it fails
type ExecQuery struct {
	// Query defines the sql statement to execute
	Query string
	// ErrorValue defines what error will be returned if the provided sql statement failed when executing
	ErrorValue string
}

// ExecWrapper is a wrapper function for xsql.DB.Exec() that allows the execution of optional queries before and after the provided query
func ExecWrapper(ctx context.Context, db xsql.DB, query ExecQuery) error {
	if err := db.Exec(ctx, xsql.Query{
		String: query.Query,
	}); err != nil {
		return errors.Wrap(err, query.ErrorValue)
	}

	return nil
}
