.PHONY: test
test:
	find . -name go.mod -execdir go test -count=1 ./... \;

.PHONY: build
build:
	find . -name go.mod -execdir go build ./... \;


.PHONY: test-race
test-race:
	go test -race -count=1 

test-race-testdirectory:
	cd testdirectory 
	go test -race -count=1