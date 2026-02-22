# Dev with Docker & VSCode

## Setup

To set up your development environment:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/k3s-argocd-cluster/s3proxy.git
    ```
2.  **Open VSCode and make use of the devcontainer**

    You may review `.devcontainer/devcontainer.json` before, however, this only is
    - downloading to the standard golang container, version 1.25.3
    - exposing port 4433 to your internal network (in case you like to talk to your
    debugging session from your internal network)
    - installing the latest version golangci-lint for your convenience
3.  **Adjust `.vscode/launch.json`**

    I am not sharing my secrets, so you need to replace the placeholder values for
    AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, S3PROXY_HOST & S3PROXY_ENCRYPT_KEY.

    You may want to adjust the args to match your setup. Default is to start s3proxy
    with no TLS, log level Debug, B2 compatibility & local caching
4.  **Start debugging**

    From a terminal, you now may talk to your service:
    ```bash
    # Local file to be encrypted locally and then forwarded to S3
    aws s3 cp test.img s3://[YOUR_BUCKET_NAME]/test.img --endpoint-url http://127.0.0.1:4433
    # Fetch and decrypt a remote file to be stored locally
    aws s3 cp s3://[YOUR_BUCKET_NAME]/test.img test.img --endpoint-url http://127.0.0.1:4433
    ```

### Of course, you can ignore the devcontainer and run manually

```bash
git clone # or gh repo clone k3s-argocd-cluster/s3proxy
cd s3proxy
docker run --rm -p 4433:4433 -v $PWD:/app -it golang:1.25.3 bash
# In VSCode, use "Attach to Running Container..." option => select golang container => open /app folder
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
export S3PROXY_HOST=xxx
export S3PROXY_ENCRYPT_KEY=toto
go run s3proxy/cmd/main.go --no-tls --level=-4

# In a different shell with aws cli installed (may be your local machine or another container) run i.e.
export AWS_ENDPOINT_URL=http://127.0.0.1:4433
echo "test" > test.txt
aws s3 cp ./test.txt s3://bucket/
aws s3 cp s3://bucket/test.txt ./test.txt
aws s3 rm s3://bucket/test.txt
```

## Linting

`golangci-lint` is used for static code analysis to ensure code quality and consistency. It combines multiple linters into a single tool.

**Enabled Linters:**
- `bodyclose`: Checks for unclosed HTTP response bodies.
- `gocognit`: Computes and checks the cognitive complexity of functions.
- `goconst`: Finds repeated strings that could be replaced by constants.
- `gocyclo`: Computes and checks the cyclomatic complexity of functions.
- `gosec`: Inspects code for security problems.
- `misspell`: Finds commonly misspelled English words.
- `revive`: A fast, configurable, extensible, flexible, and beautiful linter for Go.
- `staticcheck`: A Go static analysis tool that finds bugs and performance issues.

**How to Run:**
To run the linter, execute the following command in your development environment (when using the devcontainer this was already installed for you):
```bash
golangci-lint run
```
This will analyze the codebase and report any issues based on the configuration in `.golangci.yml`.
