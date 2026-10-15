
# 若目标机没有 make，直接照着下面的命令手敲即可。

BINDIR  := bin
LDFLAGS := -s -w
PKGS    := ./...

.PHONY: all build test vet fmt fmt-check cross verify-nft netns clean dev clean-dev

all: build

## build: 构建两个二进制到 bin/
build:
	@mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fwdd ./cmd/fwdd
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fw   ./cmd/fw
	@echo "构建完成: $(BINDIR)/fwdd, $(BINDIR)/fw"

## test: 单元测试（驱动 nft 的用例在非 Linux/非 root 下自动跳过）
test:
	go test -count=1 $(PKGS)

## test-race: 竞态检测（需 Linux 或 darwin，windows/386 不支持）
test-race:
	go test -race -count=1 $(PKGS)

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
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fwdd-linux-amd64  ./cmd/fwdd
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fw-linux-amd64    ./cmd/fw
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fwdd-linux-arm64  ./cmd/fwdd
	GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/fw-linux-arm64    ./cmd/fw

## verify-nft: 用真实 nft 校验生成的规则集语法（需 Linux + root，只校验不提交）
verify-nft:
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
