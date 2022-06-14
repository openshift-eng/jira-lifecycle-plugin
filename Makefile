# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
	lib/tmp.mk \
)

# Build configuration
git_commit=$(shell git describe --tags --always --dirty)
build_date=$(shell date -u '+%Y%m%d')
version=v${build_date}-${git_commit}

SOURCE_GIT_TAG=v1.0.0+$(shell git rev-parse --short=7 HEAD)

GO_LD_EXTRAFLAGS=-X github.com/openshift-eng/jira-lifecycle-plugin/vendor/k8s.io/client-go/pkg/version.gitCommit=$(shell git rev-parse HEAD) -X github.com/openshift-eng/jira-lifecycle-plugin/vendor/k8s.io/client-go/pkg/version.gitVersion=${SOURCE_GIT_TAG} -X k8s.io/test-infra/prow/version.Name=jira-lifecycle-plugin -X k8s.io/test-infra/prow/version.Version=${version}

