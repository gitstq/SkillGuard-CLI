<div align="center">

# 🛡️ SkillGuard-CLI

**Lightweight AI Agent Skill Security Scanner**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-brightgreen)](pyproject.toml)
[![Patterns](https://img.shields.io/badge/Patterns-44-orange)](skillguard/patterns.py)
[![Categories](https://img.shields.io/badge/Categories-16-purple)](skillguard/patterns.py)

[English](#english) | [简体中文](#simplified-chinese)

</div>

---

<a name="english"></a>
## English

### Introduction

SkillGuard is a **zero-dependency**, lightweight security scanner for AI agent skills. It detects vulnerabilities, malicious patterns, and security risks in skill files before you install them.

With **44 vulnerability patterns** across **16 categories**, SkillGuard helps you answer: **"Is this skill safe to install?"**

### Core Features

- **44 Vulnerability Patterns** across 16 security categories
- **Zero Dependencies** - Pure Python standard library
- **Beautiful TUI Dashboard** with ASCII score gauge
- **Multi-Format Reports**: Terminal, JSON, SARIF 2.1.0, Markdown
- **Multi-Platform Support**: Claude Code, Cursor, Windsurf, Copilot, Codex, Gemini, MCP
- **Fast Scanning** - Single-pass regex analysis
- **Risk Scoring** - 0-100 score with severity levels
- **Cross-Platform** - Windows, macOS, Linux

### Quick Start

```bash
# Clone the repository
git clone https://github.com/gitstq/SkillGuard-CLI.git
cd SkillGuard-CLI

# Install
pip install -e .

# Scan a skill directory
skillguard scan ./my-skill/

# Scan a single file
skillguard scan ./SKILL.md

# Output JSON report
skillguard scan ./my-skill/ --format json --output report.json

# Output SARIF for CI/CD
skillguard scan ./my-skill/ --format sarif --output report.sarif

# Only show HIGH and above
skillguard scan ./my-skill/ --severity HIGH
```

### Usage Guide

#### Scan Command

```bash
# Basic scan
skillguard scan <target>

# Options
skillguard scan <target> [options]
  --format {terminal,json,sarif,markdown}  Output format
  --output, -o <path>                      Save report to file
  --severity {CRITICAL,HIGH,MEDIUM,LOW}    Minimum severity
  --no-tui                                 Disable TUI dashboard
  --no-recursive                           Disable recursive scanning
  --category <name>                        Filter by category
```

#### List Patterns

```bash
# List all patterns
skillguard list

# Filter by severity
skillguard list --severity HIGH

# Filter by category
skillguard list --category "Prompt Injection"
```

#### Scanner Info

```bash
skillguard info
```

### Design Philosophy

SkillGuard follows these principles:

1. **Zero Dependencies** - No external packages to install or maintain
2. **Fast & Lightweight** - Single-pass scanning with minimal overhead
3. **Actionable Reports** - Every finding includes confidence score and fix recommendation
4. **CI/CD Ready** - SARIF output integrates with GitHub Advanced Security, GitLab, etc.
5. **Developer Friendly** - Beautiful TUI with clear visual hierarchy

### Packaging & Deployment

```bash
# Build distribution
make build

# Run tests
make test

# Install locally
make install
```

### Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### License

MIT License - See [LICENSE](LICENSE)

---

<a name="simplified-chinese"></a>
## 简体中文

### 项目介绍

SkillGuard 是一款**零依赖**的轻量级 AI Agent 技能安全扫描引擎。在安装技能文件之前，它能检测漏洞、恶意模式和安全风险。

拥有**44个漏洞模式**，覆盖**16个安全类别**，SkillGuard 帮助您回答：**"这个技能安全吗？"**

### 核心特性

- **44个漏洞模式**，覆盖16个安全类别
- **零依赖** - 纯 Python 标准库实现
- **精美 TUI 仪表盘**，带 ASCII 分数仪表盘
- **多格式报告**：终端、JSON、SARIF 2.1.0、Markdown
- **多平台支持**：Claude Code、Cursor、Windsurf、Copilot、Codex、Gemini、MCP
- **快速扫描** - 单次正则分析
- **风险评分** - 0-100分，带严重等级
- **跨平台** - Windows、macOS、Linux

### 快速开始

```bash
# 克隆仓库
git clone https://github.com/gitstq/SkillGuard-CLI.git
cd SkillGuard-CLI

# 安装
pip install -e .

# 扫描技能目录
skillguard scan ./my-skill/

# 扫描单个文件
skillguard scan ./SKILL.md

# 输出 JSON 报告
skillguard scan ./my-skill/ --format json --output report.json

# 输出 SARIF 用于 CI/CD
skillguard scan ./my-skill/ --format sarif --output report.sarif

# 只显示 HIGH 及以上
skillguard scan ./my-skill/ --severity HIGH
```

### 详细使用指南

#### 扫描命令

```bash
# 基础扫描
skillguard scan <目标>

# 选项
skillguard scan <目标> [选项]
  --format {terminal,json,sarif,markdown}  输出格式
  --output, -o <路径>                      保存报告到文件
  --severity {CRITICAL,HIGH,MEDIUM,LOW}    最低严重等级
  --no-tui                                 禁用 TUI 仪表盘
  --no-recursive                           禁用递归扫描
  --category <名称>                        按类别筛选
```

#### 列出模式

```bash
# 列出所有模式
skillguard list

# 按严重等级筛选
skillguard list --severity HIGH

# 按类别筛选
skillguard list --category "Prompt Injection"
```

#### 扫描器信息

```bash
skillguard info
```

### 设计思路

SkillGuard 遵循以下原则：

1. **零依赖** - 无需安装或维护外部包
2. **快速轻量** - 单次扫描，开销极小
3. **可操作报告** - 每个发现都包含置信度和修复建议
4. **CI/CD 就绪** - SARIF 输出可与 GitHub Advanced Security、GitLab 等集成
5. **开发者友好** - 精美的 TUI，清晰的视觉层次

### 打包与部署

```bash
# 构建分发包
make build

# 运行测试
make test

# 本地安装
make install
```

### 贡献指南

请参阅 [CONTRIBUTING.md](CONTRIBUTING.md)。

### 开源协议

MIT 协议 - 详见 [LICENSE](LICENSE)
