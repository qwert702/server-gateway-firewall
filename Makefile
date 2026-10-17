
# 若目标机没有 make，直接照着下面的命令手敲即可。

BINDIR  := bin
PKGS    := ./...

# 版本信息在构建时注入。VERSION 优先取 git tag，其次取短哈希，
# 都没有就退回 dev —— 不要写死常量，否则二进制里的版本迟早和仓库对不上。
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

VERSIONPKG := fwdd/internal/version
LDFLAGS := -s -w \
	-X $(VERSIONPKG).Version=$(VERSION) \
	-X $(VERSIONPKG).Commit=$(COMMIT) \
	-X $(VERSIONPKG).Date=$(DATE)

.PHONY: all build test vet fmt fmt-check cross release verify-nft netns clean dev clean-dev

all: build

## build: 构建两个二进制到 bin/
build:
	@mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fwdd ./cmd/fwdd
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fw   ./cmd/fw
	@echo "构建完成: $(BINDIR)/fwdd, $(BINDIR)/fw  (版本 $(VERSION))"

## test: 单元测试（驱动 nft 的用例在非 Linux/非 root 下自动跳过）
test:
	go test -count=1 -timeout 120s $(PKGS)

## test-race: 竞态检测（需 Linux 或 darwin，windows/386 不支持）
test-race:
	go test -race -count=1 -timeout 300s $(PKGS)

## vet: 静态检查
vet:
	go vet $(PKGS)

## fmt: 格式化
fmt:
	gofmt -w .

## fmt-check: 检查格式（CI 用）
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "以下文件未格式化:"; echo "$$out"; exit 1; fi

## cross: 交叉编译到常见 Linux 目标
cross:
	@mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fwdd-linux-amd64  ./cmd/fwdd
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fw-linux-amd64    ./cmd/fw
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fwdd-linux-arm64  ./cmd/fwdd
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fw-linux-arm64    ./cmd/fw

## release: 打包发布产物（每个目标一个 tar.gz，内含二进制、示例配置与 systemd 单元）
release:
	@mkdir -p $(BINDIR)/release
	@for target in linux/amd64 linux/arm64; do \
	  os=$${target%/*}; arch=$${target#*/}; name=fwdd-$(VERSION)-$$os-$$arch; \
	  rm -rf $(BINDIR)/release/$$name; mkdir -p $(BINDIR)/release/$$name; \
	  for bin in fwdd fw; do \
	    GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" \
	      -o $(BINDIR)/release/$$name/$$bin ./cmd/$$bin || exit 1; \
	  done; \
	  cp configs/config.example.yaml configs/policy.example.yaml $(BINDIR)/release/$$name/; \
	  cp deploy/fwdd.service $(BINDIR)/release/$$name/; \
	  tar -C $(BINDIR)/release -czf $(BINDIR)/release/$$name.tar.gz $$name; \
	  rm -rf $(BINDIR)/release/$$name; \
	  echo "  已打包 $$name.tar.gz"; \
	done
	@echo "发布产物在 $(BINDIR)/release/"

## verify-nft: 用真实 nft 校验生成的规则集语法（需 Linux + root，只校验不提交）
##
## 跑两部分：
##   1. Go 侧的 golden 测试 —— 把编译器能生成的每一种构造（IPv6、按源限速、
##      并发连接数限制、reject 模式、日志、NAT）逐个交给 `nft -c` 校验。
##      这一层覆盖的是"示例策略恰好没用到"的边角构造。
##   2. 脚本 —— 用真实示例策略走一遍完整下发与回滚。
verify-nft:
	sudo go test ./internal/backend/nftables/ -run 'Nft|Valid' -count=1 -v
	sudo ./deploy/verify-ruleset.sh

## netns: 网络命名空间端到端测试（需 Linux + root）
netns:
	sudo ./deploy/netns-test.sh

## dev: 在本地用 mock 后端起一个演示实例（无需 root）
dev: build
	@mkdir -p .dev
	@printf 'listen: 127.0.0.1:18080\nsocket: ""\nbackend: mock\ntable: fw\nfamily: inet\npolicy_file: configs/policy.example.yaml\nlog_level: info\n' > .dev/config.yaml
	@echo "启动 mock 后端演示。另开一个终端执行："
	@echo "  ./$(BINDIR)/fw -config .dev/config.yaml status"

clean:
	rm -rf $(BINDIR)

clean-dev:
	rm -rf .dev
