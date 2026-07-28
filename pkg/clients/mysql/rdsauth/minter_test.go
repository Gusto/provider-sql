package rdsauth_test

import (
	"github.com/crossplane-contrib/provider-sql/pkg/clients/mysql"
	"github.com/crossplane-contrib/provider-sql/pkg/clients/mysql/rdsauth"
)

// Compile-time proof that a *rdsauth.Minter is a mysql.TokenMinter, so it can
// be passed straight to mysql.NewWithMinter without any adapter.
var _ mysql.TokenMinter = (*rdsauth.Minter)(nil)
