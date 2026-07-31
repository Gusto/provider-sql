// Package rdsauth mints short-lived AWS RDS/Aurora IAM database
// authentication tokens for use as a MySQL connection password. A *Minter
// satisfies the mysql.TokenMinter interface structurally, so the mysql
// client package does not import this one.
package rdsauth

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/feature/rds/auth"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/pkg/errors"
)

// Minter builds RDS IAM auth tokens for a fixed (endpoint, region, dbUser)
// using ambient AWS credentials (IRSA / Pod Identity), optionally after an
// assume-role chain for cross-account access.
type Minter struct {
	endpoint string // host:port
	region   string
	dbUser   string
	creds    aws.CredentialsProvider
}

// New resolves AWS credentials from the default chain (IRSA / Pod Identity),
// applies any assume-role chain, and returns a Minter for the given target.
// endpoint is "host:port"; assumeRoleARNs is applied in order (each role is
// assumed with the previous step's credentials), mirroring the pattern in
// crossplane-provider-platform-core's internal/controller/aws/client.go.
func New(ctx context.Context, region, endpoint, dbUser string, assumeRoleARNs []string) (*Minter, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, errors.Wrap(err, "cannot load AWS config")
	}
	creds := cfg.Credentials
	for _, arn := range assumeRoleARNs {
		stsClient := sts.NewFromConfig(cfg)
		creds = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(stsClient, arn))
		cfg.Credentials = creds
	}
	return &Minter{endpoint: endpoint, region: region, dbUser: dbUser, creds: creds}, nil
}

// Mint returns a fresh RDS IAM auth token (valid ~15 minutes). Invoked once
// per new physical database connection by the MySQL client's connector.
func (m *Minter) Mint(ctx context.Context) (string, error) {
	token, err := auth.BuildAuthToken(ctx, m.endpoint, m.region, m.dbUser, m.creds)
	if err != nil {
		return "", errors.Wrap(err, "cannot build RDS IAM auth token")
	}
	return token, nil
}
