# Go module
export GO111MODULE=on
GOTEST = go test -race -coverprofile=coverage.txt -covermode=atomic
GO_PKGS?=$$(go list ./... | grep -v /vendor/)

.PHONY: test

test:
		$(GOTEST) -v $(GO_PKGS)