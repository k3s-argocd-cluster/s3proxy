#!/bin/bash
apt-get update
apt-get install -y --no-install-recommends git ssh curl unzip zsh bat

cd /tmp
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin latest
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-4 | bash

git config --global user.email "$GIT_EMAIL"
git config --global user.name "$GIT_USER"

go install -v github.com/go-delve/delve/cmd/dlv@latest