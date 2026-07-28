package mysql

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	driver "github.com/go-sql-driver/mysql"

	"github.com/crossplane-contrib/provider-sql/pkg/clients/xsql"
	xpv1 "github.com/crossplane/crossplane-runtime/v2/apis/common/v1"
)

// This test exercises go-sql-driver's client-side AllowCleartextPasswords
// gate against a live TCP listener that speaks just enough of the MySQL wire
// protocol to force the cleartext path. It exists because that path cannot be
// reproduced with a real MySQL server in CI: sha256_password is handled by the
// driver internally (RSA public-key exchange, never asks for cleartext), and
// the plugins that actually make a server request mysql_clear_password
// (authentication_pam / authentication_ldap_simple) are MySQL Enterprise-only
// and absent from any community/CI image. A protocol-level mock is the only
// way to cover the gate — which is the same gate RDS/Aurora IAM database
// authentication (AWSAuthenticationPlugin) relies on in production.
//
// The mock advertises mysql_native_password in the initial handshake and then
// issues an AuthSwitchRequest to mysql_clear_password. This ordering is
// load-bearing: if the initial handshake advertised cleartext directly, the
// driver silently falls back to native auth on ErrCleartextPassword
// (connector.go Connect), so the gate would never be observed. Only the
// auth-switch path returns the error without fallback (handleAuthResult), so
// only it genuinely proves the gate is what rejects the connection.

// writePacket frames payload with MySQL's 3-byte little-endian length prefix
// and the given sequence id, then writes it to w.
func writePacket(w io.Writer, seq byte, payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// readPacket reads one framed packet, returning its sequence id and payload.
func readPacket(r io.Reader) (seq byte, payload []byte, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[3], payload, nil
}

// initialHandshakePacket builds a protocol-10 handshake advertising
// mysql_native_password with no CLIENT_SSL bit, so a tls=false / tls=preferred
// client connects in plaintext. Byte layout mirrors what go-sql-driver's
// readHandshakePacket parses: 8-byte scramble part 1, filler, lower/upper
// capability flags, then a 13-byte scramble part 2 (12 bytes + NUL) and the
// NUL-terminated auth plugin name.
func initialHandshakePacket() []byte {
	scramble := make([]byte, 20)
	for i := range scramble {
		scramble[i] = byte(i + 1)
	}

	p := make([]byte, 0, 96)
	p = append(p, 0x0a)                   // protocol version 10
	p = append(p, "8.0.0-mock\x00"...)    // NUL-terminated server version
	p = append(p, 0x01, 0x00, 0x00, 0x00) // connection id
	p = append(p, scramble[:8]...)        // auth-plugin-data part 1
	p = append(p, 0x00)                   // filler

	var lower uint16 = 0x0001 | 0x0200 | 0x8000 // LONG_PASSWORD | PROTOCOL_41 | SECURE_CONNECTION
	p = binary.LittleEndian.AppendUint16(p, lower)
	p = append(p, 0x21, 0x02, 0x00) // character set (utf8_general_ci) + status flags (autocommit)

	var upper uint16 = 0x0008 // PLUGIN_AUTH (bit 19 -> 0x0008 in the upper word)
	p = binary.LittleEndian.AppendUint16(p, upper)
	p = append(p, 21)                  // length of auth-plugin-data
	p = append(p, make([]byte, 10)...) // reserved
	p = append(p, scramble[8:]...)     // auth-plugin-data part 2 (12 bytes)
	p = append(p, 0x00)                // NUL terminating the scramble
	p = append(p, "mysql_native_password"...)
	p = append(p, 0x00)
	return p
}

// authSwitchToCleartextPacket builds an AuthSwitchRequest steering the client
// to mysql_clear_password. The cleartext plugin ignores the scramble, but a
// real server sends one, so we do too.
func authSwitchToCleartextPacket() []byte {
	p := make([]byte, 0, 48)
	p = append(p, 0xfe) // auth switch request
	p = append(p, "mysql_clear_password"...)
	p = append(p, 0x00)
	p = append(p, make([]byte, 20)...) // auth plugin data (ignored)
	p = append(p, 0x00)
	return p
}

// okPacket builds a minimal PROTOCOL_41 OK packet: header, zero affected-rows
// and last-insert-id, autocommit status, zero warnings.
func okPacket() []byte {
	return []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
}

// startCleartextMockServer starts the wire-protocol listener on an ephemeral
// port and returns its host and port. The listener is closed via t.Cleanup.
func startCleartextMockServer(t *testing.T) (host, port string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go serveCleartextConn(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", strconv.Itoa(addr.Port)
}

// serveCleartextConn drives one connection through the auth exchange and then
// the command phase. Each server packet echoes the received sequence id + 1,
// so sequencing stays correct without hardcoding.
func serveCleartextConn(conn net.Conn) {
	defer conn.Close() //nolint:errcheck
	r := bufio.NewReader(conn)
	if err := cleartextAuthExchange(conn, r); err != nil {
		return
	}
	serveCommands(conn, r)
}

// cleartextAuthExchange sends the native handshake, switches the client to
// cleartext (where the gate fires), and finishes with an auth OK. It returns
// an error as soon as the client disconnects — notably when the gate rejects
// and the driver returns ErrCleartextPassword and hangs up without sending a
// cleartext response, so the mid-exchange read fails.
func cleartextAuthExchange(conn net.Conn, r *bufio.Reader) error {
	if err := writePacket(conn, 0, initialHandshakePacket()); err != nil {
		return err
	}
	seq, _, err := readPacket(r) // client handshake response (native auth)
	if err != nil {
		return err
	}
	if err := writePacket(conn, seq+1, authSwitchToCleartextPacket()); err != nil {
		return err
	}
	seq, _, err = readPacket(r) // cleartext auth response
	if err != nil {
		return err
	}
	return writePacket(conn, seq+1, okPacket())
}

// serveCommands replies OK to every command until the client sends COM_QUIT
// or disconnects.
func serveCommands(conn net.Conn, r *bufio.Reader) {
	for {
		seq, payload, err := readPacket(r)
		if err != nil {
			return
		}
		if len(payload) > 0 && payload[0] == 0x01 { // COM_QUIT
			return
		}
		if err := writePacket(conn, seq+1, okPacket()); err != nil {
			return
		}
	}
}

// TestNewWithConfigCleartextGate proves the mock genuinely exercises
// go-sql-driver's AllowCleartextPasswords gate rather than returning a fixed
// response: without the flag the same server and query yield
// ErrCleartextPassword, and only setting the flag lets the connection through.
func TestNewWithConfigCleartextGate(t *testing.T) {
	host, port := startCleartextMockServer(t)

	creds := map[string][]byte{
		xpv1.ResourceCredentialsSecretEndpointKey: []byte(host),
		xpv1.ResourceCredentialsSecretPortKey:     []byte(port),
		xpv1.ResourceCredentialsSecretUserKey:     []byte("admin"),
		xpv1.ResourceCredentialsSecretPasswordKey: []byte("s3cr3t"),
	}
	// tls=false keeps the mock a plain-TCP server; the provider-sql-level
	// coupling of allowCleartextPasswords to TLS is covered separately by
	// TestValidateAllowCleartextPasswords. NewWithConfig does not call that
	// guard, so this drives the driver gate in isolation.
	tlsFalse := "false"

	do := func(allow *bool) error {
		resetPoolCacheForTest() // distinct DSN per case, but keep it deterministic
		db := NewWithConfig(creds, &tlsFalse, nil, nil, allow)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return db.Exec(ctx, xsql.Query{String: "DO 1"})
	}

	t.Run("without allowCleartextPasswords the driver refuses cleartext", func(t *testing.T) {
		err := do(nil)
		if !errors.Is(err, driver.ErrCleartextPassword) {
			t.Fatalf("expected ErrCleartextPassword, got %v", err)
		}
	})

	t.Run("with allowCleartextPasswords the connection succeeds", func(t *testing.T) {
		allow := true
		if err := do(&allow); err != nil {
			t.Fatalf("expected success with allowCleartextPasswords set, got %v", err)
		}
	})
}
