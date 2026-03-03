/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/
/*
Package router implements the interception logic of s3proxy.
It classifies requests, applies middleware policies, and dispatches
transport handlers for object interception or forwarding.
*/
package router

import (
	"fmt"
	"net/http"

	"github.com/k3s-argocd-cluster/s3proxy/internal/caching"
	"github.com/k3s-argocd-cluster/s3proxy/internal/config"
	"github.com/k3s-argocd-cluster/s3proxy/internal/encryption"
	"github.com/k3s-argocd-cluster/s3proxy/internal/s3"
	logger "github.com/sirupsen/logrus"
)

// Router implements the interception logic for the s3proxy.
type Router struct {
	region  string
	tagging bool
	log     *logger.Logger
	cache   caching.Cache
	s3      *s3.Client
	crypto  *encryption.Client
	mux     http.Handler
}

// New creates a new Router.
func New(region string, tagging bool, cacheType string, log *logger.Logger) (Router, error) {
	s3Client, err := s3.NewClient(region, tagging)
	if err != nil {
		return Router{}, fmt.Errorf("creating S3 client: %w", err)
	}

	kmsStaticKey, err := config.GetKMSStaticKey()
	if err != nil {
		return Router{}, err
	}

	cryptoClient, err := encryption.New(s3Client.GetS3Client(), kmsStaticKey)
	if err != nil {
		return Router{}, fmt.Errorf("creating encryption client: %w", err)
	}

	r := Router{
		region:  region,
		tagging: tagging,
		cache:   caching.NewCache(cacheType, log),
		log:     log,
		s3:      s3Client,
		crypto:  cryptoClient,
	}
	r.mux = r.newMux()
	r.updateCacheStatsMetrics()

	return r, nil
}

// Serve is the Router's entrypoint.
func (r Router) Serve(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}
