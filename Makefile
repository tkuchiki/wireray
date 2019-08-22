PHONY: build docker_build build_linux

build:
	go build -o ./cli/wireray/wireray ./cli/wireray

docker_build:
	docker build -t wireray_build .

build_linux:
	docker run --rm -v $(abspath .):/tmp/ -t wireray_build bash -c "cd /go/src/github.com/tkuchiki/wireray; make build; mv ./cli/wireray/wireray /tmp/"
