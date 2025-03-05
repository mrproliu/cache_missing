
REPODIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

container-generate: export REPO_ROOT := $(REPODIR)
container-generate:
#	docker buildx create --use --driver-opt network=host --name cache_missing || true
#	docker buildx build --load --platform linux/amd64 -t cache_missing_build_amd64 . -f Dockerfile.build
#	docker buildx build --load --platform linux/arm64 -t cache_missing_build_arm64 . -f Dockerfile.build
	docker run --rm \
		-v "${REPODIR}":/cache_missing -w /cache_missing --platform linux/amd64 --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/cache_missing=." \
		--env HOME="/cache_missing" \
		cache_missing_build_amd64 \
		make generate
	docker run --rm \
		-v "${REPODIR}":/cache_missing -w /cache_missing --platform linux/arm64 --env MAKEFLAGS \
		--env CFLAGS="-fdebug-prefix-map=/cache_missing=." \
		--env HOME="/cache_missing" \
		cache_missing_build_arm64 \
		make generate

.PHONY: generate
generate: export REPO_ROOT := $(REPODIR)
generate:
	cd ./ && TARGET=$(if $(findstring x86_64,$(shell uname -m)),amd64,arm64) go generate ./...

run:
	CGO_ENABLED=0 go build -o cache_missing main.go && ./cache_missing
