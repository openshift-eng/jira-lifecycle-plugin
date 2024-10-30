FROM quay-proxy.ci.openshift.org/openshift/ci:openshift_release_rhel-9-release-golang-1.22-openshift-4.18
# Create non-root user for rootless podman installations
RUN groupadd --gid 1000 dev && useradd --uid 1000 --gid 1000 -m dev && mkdir /home/dev/go && chown -R dev:dev /home/dev/go
USER dev
# Use home go directories instead of /go and disable GOFLAGS='' to prevent issue caused by forcing -mod=vendor
ENV GOPATH=/home/dev/go GOCACHE=/home/dev/go/cache GOFLAGS='' PATH=/home/dev/go/bin:${PATH} GOVERSION=v0.0.0
# Install common golang tools
RUN echo $PATH && go install golang.org/x/vuln/cmd/govulncheck@latest && \
    go install golang.org/x/tools/gopls@latest && \
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    go install github.com/go-delve/delve/cmd/dlv@latest
