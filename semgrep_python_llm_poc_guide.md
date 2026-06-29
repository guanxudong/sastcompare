# 基于 Semgrep + Python 脚本 + LLM 的快速 PoC 生成方案

## 技术文档 v1.0

---

## 1. 方案概述

本方案旨在构建一条轻量级、零外部依赖（除 Semgrep 外）的安全审计流水线，用于从大型代码仓库中快速定位潜在漏洞 Sink，并自动生成可供大语言模型（LLM）分析的代码上下文，最终输出漏洞 PoC 及修复建议。

### 1.1 核心目标
- **快速**：从 Semgrep 告警到 LLM 分析输出，单条路径处理时间 < 5 分钟
- **轻量**：无需构建重型代码知识图谱（如 CodeGraph、Graphify）或 CPG 数据库（如 Joern）
- **零依赖**：除 Semgrep 外，其余环节均使用 Python 标准库实现
- **可落地**：适用于企业内部无 Rust、无复杂工具链审批的环境

### 1.2 适用场景
| 场景 | 适用性 |
|------|--------|
| 紧急漏洞响应，需快速出 PoC | ✅ 非常适合 |
| 一次性安全审计，无需长期维护 | ✅ 非常适合 |
| 大型项目深度污点分析 | ❌ 建议改用 Joern |
| CI/CD 自动化阻断 | ❌ 建议改用 Semgrep + CodeQL |

---

## 2. 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: 探测（Semgrep）                                    │
│  ├─ 输入：目标代码仓库                                       │
│  ├─ 动作：内置规则扫描，识别 Sink 候选                       │
│  └─ 输出：JSON 格式的命中结果（含文件路径、行号、规则ID）     │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: 溯源（Python 脚本）                                │
│  ├─ 输入：Semgrep 输出的 Sink 方法名 + 项目目录             │
│  ├─ 动作：递归向上搜索调用链，提取各节点方法体               │
│  └─ 输出：完整调用链 + 各节点代码片段                        │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: 分析（LLM）                                        │
│  ├─ 输入：结构化 Prompt（调用链 + 代码 + 审计任务）          │
│  ├─ 动作：语义分析、数据流判断、漏洞确认                     │
│  └─ 输出：JSON 格式审计报告（含 PoC、利用条件、修复建议）     │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Layer 1: Semgrep 探测

### 3.1 安装
```bash
# macOS
brew install semgrep

# Python
pip install semgrep

# 验证
semgrep --version
```

### 3.2 扫描命令
```bash
# 使用内置规则集扫描全仓库
semgrep --config=auto         --config=p/owasp-top-ten         --config=p/security-audit         --json         --output semgrep_results.json         ./project

# 仅扫描特定语言（如 Java）
semgrep --config=auto         --lang=java         --json         -o semgrep_results.json         ./project
```

### 3.3 输出解析
Semgrep 的 JSON 输出包含以下关键字段：

```json
{
  "results": [
    {
      "check_id": "java.lang.security.audit.sql-injection",
      "path": "src/dao/UserDAO.java",
      "start": { "line": 42, "col": 10 },
      "end": { "line": 42, "col": 30 },
      "extra": {
        "message": "Detected non-constant SQL query",
        "lines": "stmt.executeQuery(sql);"
      }
    }
  ]
}
```

**提取 Sink 方法名**：从 `path` 和 `lines` 中解析出被调用的危险方法（如 `executeQuery`）。

---

## 4. Layer 2: Python 溯源脚本

### 4.1 设计原则
- **零第三方依赖**：仅使用 Python 标准库（`os`, `re`, `json`, `pathlib`）
- **自动过滤**：跳过 `node_modules/`, `.git/`, `target/` 等目录
- **递归溯源**：从 Sink 向上逐层查找调用者，直到发现入口点
- **代码提取**：自动提取调用链上各节点的方法体

### 4.2 核心模块

#### 模块 A: 文件扫描器
```python
import os
from pathlib import Path

SKIP_DIRS = {'node_modules', '.git', 'target', 'build', 'dist', 
             'venv', '__pycache__', '.idea', '.vscode'}
SKIP_EXTS = {'.jar', '.war', '.class', '.pyc', '.png', '.jpg', 
             '.pdf', '.zip', '.tar', '.gz'}

def find_code_files(src_dir: str, lang: str = 'java') -> list:
    """递归查找所有代码文件"""
    ext_map = {'java': '.java', 'python': '.py', 'go': '.go', 
               'javascript': '.js', 'typescript': '.ts'}
    target_ext = ext_map.get(lang, '.java')
    files = []

    for root, dirs, filenames in os.walk(src_dir):
        # 跳过垃圾目录
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in filenames:
            if f.endswith(target_ext):
                filepath = os.path.join(root, f)
                # 简单过滤二进制文件
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as fh:
                        fh.read(1024)
                    files.append(filepath)
                except:
                    continue
    return files
```

#### 模块 B: 调用链溯源器
```python
import re

METHOD_PATTERNS = {
    'java': re.compile(
        r'(?:public|private|protected|static|final|\s)+'
        r'(?:<\w+>\s+)?'
        r'(?:\w+(?:\[\])*\s+)+'
        r'(\w+)\s*\([^)]*\)\s*\{'),
    'python': re.compile(r'(?:async\s+)?def\s+(\w+)\s*\([^:]*:'),
}

def search_callers(files: list, method_name: str) -> list:
    """搜索谁调用了指定方法"""
    pattern = re.compile(rf'(?:|\.)({re.escape(method_name)})\s*\(')
    matches = []
    for filepath in files:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line_no, line in enumerate(f, 1):
                    if pattern.search(line):
                        matches.append({
                            'file': filepath,
                            'line': line_no,
                            'text': line.strip()
                        })
        except:
            continue
    return matches

def extract_method_name(file_path: str, line_no: int, lang: str) -> str:
    """从匹配行向上查找方法定义"""
    pattern = METHOD_PATTERNS.get(lang)
    if not pattern:
        return 'unknown'
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        for i in range(line_no - 1, -1, -1):
            match = pattern.search(lines[i])
            if match:
                return match.group(1)
    except:
        pass
    return 'unknown'

def trace_call_chain(files: list, sink_method: str, lang: str, max_depth: int = 5):
    """从 Sink 向上溯源"""
    chain = [{'name': sink_method, 'file': 'SINK', 'line': 0, 'type': 'sink'}]
    current = sink_method

    for depth in range(max_depth):
        matches = search_callers(files, current)
        if not matches:
            break

        # 取第一个匹配（实际可扩展为处理多分支）
        match = matches[0]
        caller = extract_method_name(match['file'], match['line'], lang)

        chain.append({
            'name': caller,
            'file': match['file'],
            'line': match['line'],
            'type': 'caller'
        })

        # 入口点判断
        if any(k in caller.lower() for k in ['controller', 'servlet', 'main', 
                                              'handler', 'doget', 'dopost']):
            break
        current = caller

    return chain
```

#### 模块 C: 代码提取器
```python
def extract_method_body(file_path: str, method_name: str, lang: str) -> str:
    """提取方法体代码（简化版）"""
    if file_path == 'SINK':
        return f"// SINK: {method_name}\n// 请从 Semgrep 结果中手动确认代码"

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except:
        return f"// 无法读取 {file_path}"

    if lang == 'java':
        # 匹配 Java 方法体（简化版，匹配到下一个方法定义或类结束）
        pattern = re.compile(
            rf'((?:public|private|protected|static|final|\s)+'
            rf'(?:<\w+>\s+)?'
            rf'(?:\w+(?:\[\])*\s+)+'
            rf'{re.escape(method_name)}\s*\([^{{]*\{{)',
            re.DOTALL
        )
        match = pattern.search(content)
        if match:
            start = match.start()
            brace_count = 0
            i = content.find('{', start)
            for i in range(i, len(content)):
                if content[i] == '{':
                    brace_count += 1
                elif content[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        break
            body = content[start:i+1]
            lines = body.split('\n')
            if len(lines) > 100:
                body = '\n'.join(lines[:100]) + '\n// ... (truncated)'
            return body

    return f"// 方法体提取未实现: {method_name}"
```

---

## 5. Layer 3: LLM Prompt 设计

### 5.1 Prompt 模板
```
你是一位资深代码安全审计员。以下是从 Sink 向上溯源得到的完整调用链。

【审计目标】
判断从入口到 Sink 的数据流路径上，用户输入是否被污染，是否存在有效的安全控制。

【调用链】
{{call_chain}}

【代码详情】
{{code_blocks}}

【任务要求】
1. 识别入口参数中哪些是外部可控的（HTTP参数、请求体、文件上传、环境变量等）
2. 追踪该参数是否通过调用链逐层传递到了 Sink
3. 检查传递过程中是否被：
   - 重新赋值（如 hardcoded）
   - 类型转换（如 int 转换后拼接）
   - Sanitization（如正则过滤、参数化查询、ORM 封装）
4. 判断最终到达 Sink 时是否仍存在注入/执行/反序列化等风险
5. 如果存在漏洞，给出：
   - 漏洞类型（如 SQL Injection, Command Injection）
   - 利用条件（如需要管理员权限、需要特定参数）
   - CVSS 风险等级（Critical/High/Medium/Low）
   - 修复建议（代码级）
   - 概念验证（PoC）payload

【输出格式】
严格输出以下 JSON 格式，不要添加额外解释：
{
  "vulnerable": true/false,
  "vuln_type": "SQL Injection / Command Injection / etc",
  "confidence": "high/medium/low",
  "taint_path": "参数A -> 方法B -> 方法C -> Sink",
  "sanitization": "none / insufficient / effective",
  "cvss": "7.5",
  "exploit_conditions": "...",
  "poc_payload": "...",
  "fix_suggestion": "...",
  "reason": "..."
}
```

### 5.2 上下文压缩技巧
如果调用链过长或方法体过大，需进行切片：
- 仅保留与 Sink 参数相关的赋值、传递、条件分支
- 删除日志、注释、无关业务逻辑
- 对超过 100 行的方法体，提取前 30 行 + 包含目标参数的代码行 + 后 10 行

---

## 6. 完整工作流示例

### 6.1 步骤一：Semgrep 扫描
```bash
semgrep --config=p/owasp-top-ten --json -o results.json ./src
```

从 `results.json` 中提取 Sink：`UserDAO.executeQuery`

### 6.2 步骤二：Python 溯源
```bash
python3 sink_tracer.py ./src executeQuery java
```

输出示例：
```
============================================================
从 Sink 'executeQuery' 开始溯源
项目目录: ./src
============================================================

[1/3] 扫描 java 代码文件...
      找到 156 个文件

[2/3] 逐层向上溯源...
  第 1 层: 找到 3 个调用者
    -> findByUsername @ src/dao/UserDAO.java:42
  第 2 层: 找到 2 个调用者
    -> login @ src/service/UserService.java:30
  第 3 层: 找到 2 个调用者
    -> handleRequest @ src/controller/UserController.java:15

  ✅ 到达入口点: handleRequest

[3/3] 提取调用链代码...

============================================================
溯源完成！生成的 LLM Prompt 已保存到 sink_analysis_prompt.txt
============================================================
```

### 6.3 步骤三：LLM 分析
将 `sink_analysis_prompt.txt` 内容复制到 ChatGPT / Claude / 内部 LLM，获取 JSON 审计报告。

---

## 7. 局限性与注意事项

### 7.1 已知局限
| 局限 | 说明 | 缓解方案 |
|------|------|---------|
| 正则匹配不精确 | 方法重载、匿名类、lambda 可能误报/漏报 | 结合行号人工校验；或改用 tree-sitter |
| 无数据流分析 | 只能给 LLM 调用链，不能精确追踪参数传递 | LLM 语义判断；复杂场景改用 Joern |
| 无跨文件全局变量追踪 | 通过类成员/静态变量传递的数据流会断 | 手动补充相关类代码到 Prompt |
| 大仓库性能 | 每次溯源都全量扫描文件 | 缓存文件列表；或改用 CodeGraph 索引 |
| 上下文窗口限制 | 调用链过长（>5层）或方法体过大可能超 token | 程序切片，仅保留污点相关代码 |

### 7.2 与 Joern 的对比
| 能力 | 本方案 | Joern |
|------|--------|-------|
| 安装成本 | 极低 | 高（需 JVM + 构建 CPG） |
| 首次分析延迟 | 秒级 | 分钟级（CPG 构建） |
| 跨过程数据流 | ❌ 依赖 LLM 语义 | ✅ 精确 DDG/DFG |
| 污点分析精度 | 中（LLM 判断） | 高（图遍历） |
| 大规模自动化 | 差 | 好 |
| 紧急 PoC 产出 | ✅ 快 | ❌ 慢 |

### 7.3 升级路径
当本方案遇到瓶颈时，按以下顺序升级：
1. **Python 脚本 → tree-sitter 解析**：提升方法提取精度
2. **tree-sitter → CodeGraph**：建立持久化索引，加速反复查询
3. **CodeGraph → Joern**：当需要精确数据流验证时，引入 CPG

---

## 8. 附录

### 8.1 完整脚本（单文件版）
见 `sink_tracer.py`（本文档配套脚本）。

### 8.2 推荐 Semgrep 规则集
- `p/owasp-top-ten`：OWASP Top 10 覆盖
- `p/security-audit`：通用安全审计
- `p/sql-injection`：SQL 注入专项
- `p/command-injection`：命令注入专项
- `p/xss`：跨站脚本专项

### 8.3 推荐 LLM 模型
- **Claude 3.5 Sonnet / GPT-4o**：高准确率，适合复杂逻辑判断
- **GPT-4o-mini / Claude 3 Haiku**：低成本，适合批量初筛
- **内部部署模型**：数据隐私要求高的场景

---

*文档版本: 1.0*
*最后更新: 2026-06-29*
