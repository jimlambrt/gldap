.PHONY: test
test:
	go test -race -count=1 ./... 

.PHONY: build
build:
	go build ./... 

.PHONY: tools
tools:
	go generate -tags tools tools/tools.go


.PHONY: fmt
fmt:
	gofumpt -w $$(find . -name '*.go')