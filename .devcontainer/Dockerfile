FROM quay-proxy.ci.openshift.org/openshift/ci:openshift_release_rhel-9-release-golang-1.26-openshift-5.0
# /etc/pki permissions are currently broken; set execute permission on /etc/pki directories to allow traversal
RUN chmod -R +x /etc/pki/
# Create non-root user for rootless podman installations
RUN groupadd --gid 1000 dev && useradd --uid 1000 --gid 1000 -m dev && mkdir /home/dev/go && chown -R dev:dev /home/dev/go
USER dev
# Use home go directories instead of /go and disable GOFLAGS='' to prevent issue caused by forcing -mod=vendor
ENV GOPATH=/home/dev/go GOCACHE=/home/dev/go/cache GOFLAGS='' PATH=/home/dev/go/bin:${PATH} GOVERSION=v0.0.0
# Install common golang tools
RUN echo $PATH && go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install golang.org/x/tools/gopls@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest && \
    go install github.com/mikefarah/yq/v4@latest && \
    go clean -cache -modcache

# golangci-lint recommends pulling the prebuilt binary instead of building from source
RUN curl -sSfL https://golangci-lint.run/install.sh | sh -s -- -b $(go env GOPATH)/bin
