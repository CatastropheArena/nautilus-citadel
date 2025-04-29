REGISTRY := local
.DEFAULT_GOAL :=
.PHONY: default

# 检查git仓库是否存在，如果不存在则初始化
ENSURE_GIT := $(shell if [ ! -d .git ]; then git init; fi)

default: out/enclaveos.tar

out:
	mkdir out

out/enclaveos.tar: out ensure-git \
	$(shell git ls-files \
		src/init \
		src/aws \
		src/nautilus-server \
		src/system \
	)
	docker build \
		--tag $(REGISTRY)/enclaveos \
		--progress=plain \
		--output type=local,rewrite-timestamp=true,dest=out\
		-f Containerfile \
		.

.PHONY: ensure-git
ensure-git:
	@if [ ! -d .git ]; then \
		echo "初始化git仓库..."; \
		git init; \
	fi

.PHONY: run
run: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path out/nitro.eif

.PHONY: run-debug
run-debug: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512M \
		--eif-path out/nitro.eif \
		--debug-mode \
		--attach-console