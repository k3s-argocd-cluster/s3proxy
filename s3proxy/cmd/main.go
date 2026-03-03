/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/
/*
Package main parses command line flags and starts the s3proxy server.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"net"

	"github.com/k3s-argocd-cluster/s3proxy/internal/app"
	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
	logger "github.com/sirupsen/logrus"
)

const (
	// defaultDataPort is the default data port to listen on.
	defaultDataPort = 4433
	// defaultOpsPort is the default operations port to listen on.
	defaultOpsPort = 9001
	// defaultIP is the default IP to listen on.
	defaultIP = "0.0.0.0"
	// defaultRegion is the default AWS region to use.
	defaultRegion = "eu-west-1"
	// defaultCertLocation is the default location of the TLS certificate.
	defaultCertLocation = "/etc/s3proxy/certs"
	// defaultLogLevel is the default log level.
	defaultLogLevel = 0
	// defaultCacheType is no caching at all.
	defaultCacheType = "none"
)

func main() {
	flags, err := parseFlags()
	if err != nil {
		panic(err)
	}

	log := logger.New()
	switch {
	case flags.logLevel < -1:
		log.SetLevel(logger.TraceLevel)
	case flags.logLevel == -1:
		log.SetLevel(logger.DebugLevel)
	case flags.logLevel == 0:
		log.SetLevel(logger.InfoLevel)
	case flags.logLevel == 1:
		log.SetLevel(logger.WarnLevel)
	case flags.logLevel >= 2:
		log.SetLevel(logger.ErrorLevel)
	default:
		log.SetLevel(logger.InfoLevel)
	}

	if err := config.LoadConfig(); err != nil {
		panic(err)
	}

	if err := config.ValidateConfiguration(); err != nil {
		log.WithError(err).Fatal("configuration validation failed")
	}

	if err := app.Run(context.Background(), app.Config{
		NoTLS:        flags.noTLS,
		IP:           flags.ip,
		DataPort:     flags.dataPort,
		OpsPort:      flags.opsPort,
		Region:       flags.region,
		CertLocation: flags.certLocation,
		NoTagging:    flags.noTagging,
		CacheType:    flags.cacheType,
	}, log); err != nil {
		panic(err)
	}
}

func parseFlags() (cmdFlags, error) {
	noTLS := flag.Bool("no-tls", false, "disable TLS")
	ip := flag.String("ip", defaultIP, "ip to listen on")
	dataPort := flag.Int("port", defaultDataPort, "data port to listen on")
	opsPort := flag.Int("ops-port", defaultOpsPort, "ops port for /metrics, /healthz and /readyz")
	region := flag.String("region", defaultRegion, "AWS region in which target bucket is located")
	certLocation := flag.String("cert", defaultCertLocation, "location of TLS certificate")
	level := flag.Int("level", defaultLogLevel, "log level")
	noTagging := flag.Bool("no-tagging", false, "disable S3 object tagging (i.e. x-amz-tagging header), may be helpful for backends such as BackBlaze B2")
	cacheType := flag.String("cache", defaultCacheType, "different caching types, currently 'none' or 'memory'")

	flag.Parse()

	netIP := net.ParseIP(*ip)
	if netIP == nil {
		return cmdFlags{}, fmt.Errorf("not a valid IPv4 address: %s", *ip)
	}

	return cmdFlags{
		noTLS:        *noTLS,
		ip:           netIP.String(),
		dataPort:     *dataPort,
		opsPort:      *opsPort,
		region:       *region,
		certLocation: *certLocation,
		logLevel:     *level,
		noTagging:    *noTagging,
		cacheType:    *cacheType,
	}, nil
}

type cmdFlags struct {
	noTLS        bool
	ip           string
	dataPort     int
	opsPort      int
	region       string
	certLocation string
	noTagging    bool
	logLevel     int
	cacheType    string
}
