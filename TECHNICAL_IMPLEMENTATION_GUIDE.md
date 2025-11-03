# Technical Implementation Guide: SAST Tool Development

## Quick Start: Build Your First Scanner in 2 Weeks

This guide provides hands-on technical details for building your SAST tool MVP.

---

## Part 1: Architecture Decision

### Option A: Rust-based (Recommended for Performance)

**Pros**:
- 3-5x faster than alternatives
- Memory safety built-in
- Excellent concurrency
- Growing security tools ecosystem

**Cons**:
- Steeper learning curve
- Smaller talent pool
- Longer development time

**Best for**: If you have Rust expertise or prioritize performance above all

### Option B: Go-based (Recommended for Speed-to-Market)

**Pros**:
- Easy to learn and hire for
- Great concurrency primitives
- Fast compilation
- Good performance (fast enough)
- Large ecosystem

**Cons**:
- Not as fast as Rust
- Less strict type system

**Best for**: Quick MVP, easier to scale team

### Option C: TypeScript/Node.js (Quick MVP)

**Pros**:
- Fastest to prototype
- Huge ecosystem
- Easy to hire developers
- Can reuse for web dashboard

**Cons**:
- Slower performance
- Memory management issues at scale

**Best for**: Proof of concept only

**Recommendation**: Start with **Go** for MVP, consider Rust rewrite later if needed.

---

## Part 2: Core Components Deep Dive

### 2.1 Parser Layer

#### Using Tree-sitter (Recommended)

```go
package parser

import (
    sitter "github.com/smacker/go-tree-sitter"
    "github.com/smacker/go-tree-sitter/javascript"
    "github.com/smacker/go-tree-sitter/python"
    "github.com/smacker/go-tree-sitter/java"
)

type Parser struct {
    jsParser     *sitter.Parser
    pyParser     *sitter.Parser
    javaParser   *sitter.Parser
}

func NewParser() *Parser {
    return &Parser{
        jsParser:   createParser(javascript.GetLanguage()),
        pyParser:   createParser(python.GetLanguage()),
        javaParser: createParser(java.GetLanguage()),
    }
}

func createParser(lang *sitter.Language) *sitter.Parser {
    parser := sitter.NewParser()
    parser.SetLanguage(lang)
    return parser
}

func (p *Parser) ParseFile(filePath string, language string) (*sitter.Tree, error) {
    content, err := os.ReadFile(filePath)
    if err != nil {
        return nil, err
    }

    var parser *sitter.Parser
    switch language {
    case "javascript", "typescript":
        parser = p.jsParser
    case "python":
        parser = p.pyParser
    case "java":
        parser = p.javaParser
    default:
        return nil, fmt.Errorf("unsupported language: %s", language)
    }

    return parser.ParseCtx(context.Background(), nil, content)
}
```

#### AST Node Traversal

```go
func TraverseTree(tree *sitter.Tree, visitor func(*sitter.Node) error) error {
    root := tree.RootNode()
    return traverseNode(root, visitor)
}

func traverseNode(node *sitter.Node, visitor func(*sitter.Node) error) error {
    if err := visitor(node); err != nil {
        return err
    }

    for i := 0; i < int(node.ChildCount()); i++ {
        child := node.Child(i)
        if err := traverseNode(child, visitor); err != nil {
            return err
        }
    }

    return nil
}
```

### 2.2 Rule Engine

#### Rule Definition Format (YAML)

```yaml
# rules/sql-injection-concatenation.yml
id: sql-injection-concat
name: SQL Injection via String Concatenation
description: Detects SQL queries built using string concatenation
severity: critical
cwe: CWE-89
owasp: A03:2021 - Injection
language: javascript
confidence: high

patterns:
  # Pattern 1: Direct concatenation in query methods
  - pattern: |
      $DB.$METHOD($QUERY + $INPUT)
  - metavariable-pattern:
      metavariable: $METHOD
      patterns:
        - pattern-either:
            - pattern: query
            - pattern: execute
            - pattern: exec
            - pattern: run

  # Pattern 2: Template literals with user input
  - pattern: |
      $DB.$METHOD(`...${$INPUT}...`)

sources:
  - pattern: req.body
  - pattern: req.params
  - pattern: req.query
  - pattern: req.headers

sinks:
  - pattern: db.query(...)
  - pattern: connection.execute(...)
  - pattern: pool.query(...)

fix:
  message: Use parameterized queries instead of string concatenation
  suggestion: |
    Replace:
      db.query("SELECT * FROM users WHERE id = " + userId)
    With:
      db.query("SELECT * FROM users WHERE id = ?", [userId])

examples:
  vulnerable:
    - code: |
        const userId = req.params.id;
        db.query("SELECT * FROM users WHERE id = " + userId);
    - code: |
        db.query(`SELECT * FROM users WHERE name = '${req.body.name}'`);

  safe:
    - code: |
        const userId = req.params.id;
        db.query("SELECT * FROM users WHERE id = ?", [userId]);
    - code: |
        const stmt = db.prepare("SELECT * FROM users WHERE name = ?");
        stmt.get(req.body.name);
```

#### Rule Engine Implementation

```go
package rules

type Rule struct {
    ID          string   `yaml:"id"`
    Name        string   `yaml:"name"`
    Description string   `yaml:"description"`
    Severity    string   `yaml:"severity"`
    CWE         string   `yaml:"cwe"`
    OWASP       string   `yaml:"owasp"`
    Language    string   `yaml:"language"`
    Confidence  string   `yaml:"confidence"`
    Patterns    []Pattern `yaml:"patterns"`
    Sources     []Pattern `yaml:"sources"`
    Sinks       []Pattern `yaml:"sinks"`
    Fix         Fix      `yaml:"fix"`
}

type Pattern struct {
    Pattern             string            `yaml:"pattern"`
    PatternEither       []Pattern         `yaml:"pattern-either"`
    MetavariablePattern MetavariableMatch `yaml:"metavariable-pattern"`
}

type Fix struct {
    Message    string `yaml:"message"`
    Suggestion string `yaml:"suggestion"`
}

type RuleEngine struct {
    rules map[string]*Rule
}

func (re *RuleEngine) LoadRules(rulesDir string) error {
    files, err := filepath.Glob(filepath.Join(rulesDir, "*.yml"))
    if err != nil {
        return err
    }

    for _, file := range files {
        rule, err := loadRule(file)
        if err != nil {
            return err
        }
        re.rules[rule.ID] = rule
    }

    return nil
}

func (re *RuleEngine) Scan(tree *sitter.Tree, language string) []*Finding {
    findings := []*Finding{}

    for _, rule := range re.rules {
        if rule.Language != language {
            continue
        }

        matches := re.matchRule(tree, rule)
        findings = append(findings, matches...)
    }

    return findings
}

type Finding struct {
    RuleID      string
    Severity    string
    FilePath    string
    LineNumber  int
    ColumnStart int
    ColumnEnd   int
    Snippet     string
    Message     string
    Fix         string
    Confidence  float64
}
```

### 2.3 Taint Analysis Engine

This is critical for finding real vulnerabilities.

```go
package taint

type TaintAnalyzer struct {
    sources map[string]bool
    sinks   map[string]bool

    // Track data flow
    taintedVars map[string]*TaintInfo
}

type TaintInfo struct {
    SourceLocation Location
    FlowPath       []Location
    IsSanitized    bool
}

func (ta *TaintAnalyzer) Analyze(tree *sitter.Tree, sources, sinks []Pattern) []*Finding {
    // Step 1: Identify all sources (user input)
    sourcesFound := ta.findSources(tree, sources)

    // Step 2: Track data flow through the code
    taintedPaths := ta.trackDataFlow(tree, sourcesFound)

    // Step 3: Check if tainted data reaches sinks
    findings := ta.checkSinks(tree, taintedPaths, sinks)

    return findings
}

func (ta *TaintAnalyzer) trackDataFlow(tree *sitter.Tree, sources []Location) map[string]*TaintInfo {
    tainted := make(map[string]*TaintInfo)

    TraverseTree(tree, func(node *sitter.Node) error {
        switch node.Type() {
        case "variable_declarator":
            // const userId = req.params.id  <-- Track this
            varName := node.ChildByFieldName("name").Content()
            value := node.ChildByFieldName("value")

            if ta.isTainted(value) {
                tainted[varName] = &TaintInfo{
                    SourceLocation: getLocation(value),
                    FlowPath:       []Location{getLocation(node)},
                    IsSanitized:    false,
                }
            }

        case "assignment_expression":
            // userId = req.body.id  <-- Track reassignments
            left := node.ChildByFieldName("left").Content()
            right := node.ChildByFieldName("right")

            if ta.isTainted(right) {
                tainted[left] = &TaintInfo{
                    SourceLocation: getLocation(right),
                    FlowPath:       []Location{getLocation(node)},
                }
            }

        case "call_expression":
            // Check for sanitization functions
            funcName := node.ChildByFieldName("function").Content()
            if isSanitizer(funcName) {
                // Mark variables as sanitized
                args := node.ChildByFieldName("arguments")
                for _, arg := range getArguments(args) {
                    if info, exists := tainted[arg]; exists {
                        info.IsSanitized = true
                    }
                }
            }
        }

        return nil
    })

    return tainted
}

func isSanitizer(funcName string) bool {
    sanitizers := []string{
        "escape",
        "sanitize",
        "validate",
        "parseInt",
        "parseFloat",
        // Add more based on framework
    }

    for _, s := range sanitizers {
        if strings.Contains(funcName, s) {
            return true
        }
    }
    return false
}
```

### 2.4 Knowledge Base Converter

Convert your 96 MD files into rules automatically.

```go
package converter

import (
    "regexp"
    "strings"
)

type MarkdownRule struct {
    Title       string
    Description string
    RegexPattern string
    VulnCode    string
    SafeCode    string
}

func ConvertMarkdownToRules(mdFile string) ([]*Rule, error) {
    content, err := os.ReadFile(mdFile)
    if err != nil {
        return nil, err
    }

    rules := []*Rule{}
    sections := parseMarkdownSections(string(content))

    for _, section := range sections {
        rule := &Rule{
            ID:          generateID(section.Title),
            Name:        section.Title,
            Description: section.Description,
            Severity:    inferSeverity(section.Title),
            Language:    inferLanguage(mdFile),
        }

        // Convert regex to tree-sitter pattern
        if section.RegexPattern != "" {
            pattern, err := regexToPattern(section.RegexPattern)
            if err == nil {
                rule.Patterns = []Pattern{{Pattern: pattern}}
            }
        }

        // Extract examples
        if section.VulnCode != "" {
            rule.Examples.Vulnerable = []Example{{Code: section.VulnCode}}
        }
        if section.SafeCode != "" {
            rule.Examples.Safe = []Example{{Code: section.SafeCode}}
        }

        rules = append(rules, rule)
    }

    return rules, nil
}

func regexToPattern(regex string) (string, error) {
    // This is complex - you need to map regex patterns to AST patterns
    // For simple cases:

    // Example: \.innerHTML\s*=\s*(?!['"`])
    // Converts to tree-sitter pattern:
    // (assignment_expression
    //   left: (member_expression property: (property_identifier) @prop)
    //   right: (_) @value
    //   (#eq? @prop "innerHTML"))

    mapping := map[string]string{
        `\.innerHTML\s*=\s*(?!['"\` + "`" + `])`: `
(assignment_expression
  left: (member_expression
    property: (property_identifier) @prop)
  right: (identifier) @value)
  (#eq? @prop "innerHTML")
`,
        // Add more mappings
    }

    if pattern, exists := mapping[regex]; exists {
        return pattern, nil
    }

    return "", fmt.Errorf("no mapping for regex: %s", regex)
}
```

---

## Part 3: Building the MVP

### 3.1 Project Structure

```
sast-tool/
├── cmd/
│   └── scanner/
│       └── main.go              # CLI entry point
├── internal/
│   ├── parser/
│   │   ├── parser.go            # AST parser
│   │   └── traversal.go         # Tree traversal
│   ├── rules/
│   │   ├── engine.go            # Rule engine
│   │   ├── loader.go            # Rule loading
│   │   └── matcher.go           # Pattern matching
│   ├── taint/
│   │   ├── analyzer.go          # Taint analysis
│   │   └── tracker.go           # Data flow tracking
│   ├── converter/
│   │   └── markdown.go          # Convert MD to rules
│   └── reporter/
│       ├── json.go              # JSON output
│       ├── sarif.go             # SARIF format
│       └── html.go              # HTML report
├── pkg/
│   └── models/
│       ├── finding.go           # Finding data structure
│       └── rule.go              # Rule data structure
├── rules/
│   ├── javascript/
│   │   ├── sql-injection.yml
│   │   ├── xss.yml
│   │   └── ...
│   ├── python/
│   └── java/
├── tests/
│   ├── testdata/
│   │   ├── vulnerable/          # Test vulnerable code
│   │   └── safe/                # Test safe code
│   └── integration/
├── scripts/
│   └── convert-rules.sh         # Convert MD files
├── go.mod
├── go.sum
└── README.md
```

### 3.2 CLI Implementation

```go
// cmd/scanner/main.go
package main

import (
    "flag"
    "fmt"
    "os"

    "github.com/yourusername/sast-tool/internal/parser"
    "github.com/yourusername/sast-tool/internal/rules"
    "github.com/yourusername/sast-tool/internal/reporter"
)

func main() {
    // CLI flags
    pathFlag := flag.String("path", ".", "Path to scan")
    langFlag := flag.String("language", "auto", "Language to scan")
    rulesDir := flag.String("rules", "./rules", "Rules directory")
    outputFormat := flag.String("output", "text", "Output format: text, json, sarif, html")
    severityFlag := flag.String("severity", "all", "Severity filter: critical, high, medium, low, info, all")
    fixFlag := flag.Bool("fix", false, "Show fix suggestions")

    flag.Parse()

    // Initialize scanner
    scanner := &Scanner{
        parser:      parser.NewParser(),
        ruleEngine:  rules.NewEngine(),
        path:        *pathFlag,
        language:    *langFlag,
        rulesDir:    *rulesDir,
    }

    // Load rules
    if err := scanner.ruleEngine.LoadRules(*rulesDir); err != nil {
        fmt.Fprintf(os.Stderr, "Error loading rules: %v\n", err)
        os.Exit(1)
    }

    // Scan
    findings, err := scanner.Scan()
    if err != nil {
        fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
        os.Exit(1)
    }

    // Filter by severity
    findings = filterBySeverity(findings, *severityFlag)

    // Generate report
    var reportWriter reporter.Reporter
    switch *outputFormat {
    case "json":
        reportWriter = reporter.NewJSONReporter()
    case "sarif":
        reportWriter = reporter.NewSARIFReporter()
    case "html":
        reportWriter = reporter.NewHTMLReporter()
    default:
        reportWriter = reporter.NewTextReporter()
    }

    report := reportWriter.Generate(findings, *fixFlag)
    fmt.Println(report)

    // Exit code
    if hasCritical(findings) {
        os.Exit(1)
    }
}

type Scanner struct {
    parser     *parser.Parser
    ruleEngine *rules.RuleEngine
    path       string
    language   string
    rulesDir   string
}

func (s *Scanner) Scan() ([]*models.Finding, error) {
    findings := []*models.Finding{}

    // Walk directory
    err := filepath.Walk(s.path, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }

        if info.IsDir() {
            return nil
        }

        // Detect language
        lang := detectLanguage(path)
        if s.language != "auto" && lang != s.language {
            return nil
        }

        // Parse file
        tree, err := s.parser.ParseFile(path, lang)
        if err != nil {
            return err
        }

        // Run rules
        fileFindings := s.ruleEngine.Scan(tree, lang)
        for _, f := range fileFindings {
            f.FilePath = path
        }

        findings = append(findings, fileFindings...)

        return nil
    })

    return findings, err
}
```

### 3.3 Output Formats

#### SARIF (Industry Standard)

```go
package reporter

import (
    "encoding/json"
    "github.com/yourusername/sast-tool/pkg/models"
)

type SARIFReporter struct{}

func (r *SARIFReporter) Generate(findings []*models.Finding, showFix bool) string {
    sarif := &SARIFReport{
        Version: "2.1.0",
        Runs: []SARIFRun{{
            Tool: SARIFTool{
                Driver: SARIFDriver{
                    Name:    "SecureCode Scanner",
                    Version: "1.0.0",
                    Rules:   convertRulesToSARIF(findings),
                },
            },
            Results: convertFindingsToSARIF(findings, showFix),
        }},
    }

    output, _ := json.MarshalIndent(sarif, "", "  ")
    return string(output)
}

type SARIFReport struct {
    Version string     `json:"version"`
    Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
    Tool    SARIFTool     `json:"tool"`
    Results []SARIFResult `json:"results"`
}

type SARIFResult struct {
    RuleID  string               `json:"ruleId"`
    Level   string               `json:"level"`
    Message SARIFMessage         `json:"message"`
    Locations []SARIFLocation    `json:"locations"`
    Fixes   []SARIFFix           `json:"fixes,omitempty"`
}
```

---

## Part 4: AI Integration

### 4.1 LLM-Powered Validation

```go
package ai

import (
    "context"
    "github.com/sashabaranov/go-openai"
)

type AIValidator struct {
    client *openai.Client
}

func (v *AIValidator) ValidateFinding(finding *models.Finding, code string) (*ValidationResult, error) {
    prompt := fmt.Sprintf(`You are a security expert reviewing a potential vulnerability.

Finding:
- Type: %s
- Severity: %s
- Location: %s:%d
- Description: %s

Code:
%s

Question: Is this a true positive vulnerability, or a false positive? Explain your reasoning.
Consider:
1. Is user input actually reaching this code path?
2. Are there sanitization functions being used?
3. What is the actual risk if exploited?
4. Are there framework-level protections?

Respond in JSON format:
{
  "is_vulnerable": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "explanation",
  "severity_adjustment": "critical/high/medium/low/info",
  "fix_suggestion": "specific code fix"
}`,
        finding.RuleID,
        finding.Severity,
        finding.FilePath,
        finding.LineNumber,
        finding.Message,
        code,
    )

    resp, err := v.client.CreateChatCompletion(
        context.Background(),
        openai.ChatCompletionRequest{
            Model: openai.GPT4,
            Messages: []openai.ChatCompletionMessage{{
                Role:    openai.ChatMessageRoleUser,
                Content: prompt,
            }},
            Temperature: 0.1, // Low temperature for consistent results
        },
    )

    if err != nil {
        return nil, err
    }

    var result ValidationResult
    json.Unmarshal([]byte(resp.Choices[0].Message.Content), &result)

    return &result, nil
}

type ValidationResult struct {
    IsVulnerable       bool    `json:"is_vulnerable"`
    Confidence         float64 `json:"confidence"`
    Reasoning          string  `json:"reasoning"`
    SeverityAdjustment string  `json:"severity_adjustment"`
    FixSuggestion      string  `json:"fix_suggestion"`
}
```

### 4.2 Auto-Fix Generation

```go
func (v *AIValidator) GenerateFix(finding *models.Finding, code string) (string, error) {
    prompt := fmt.Sprintf(`Generate a secure code fix for this vulnerability.

Vulnerability: %s
Code:
%s

Provide:
1. The fixed code
2. Explanation of the fix
3. Any additional security recommendations

Format as:
{
  "fixed_code": "...",
  "explanation": "...",
  "recommendations": [...]
}`,
        finding.Message,
        code,
    )

    // Call LLM
    resp, err := v.client.CreateChatCompletion(...)

    var fix FixResult
    json.Unmarshal([]byte(resp.Choices[0].Message.Content), &fix)

    return fix.FixedCode, nil
}
```

---

## Part 5: Testing Strategy

### 5.1 Accuracy Testing

```go
// tests/accuracy_test.go
package tests

func TestSQLInjectionDetection(t *testing.T) {
    testCases := []struct {
        name        string
        code        string
        shouldFind  bool
        severity    string
    }{
        {
            name: "Direct concatenation",
            code: `
                const userId = req.params.id;
                db.query("SELECT * FROM users WHERE id = " + userId);
            `,
            shouldFind: true,
            severity:   "critical",
        },
        {
            name: "Parameterized query (safe)",
            code: `
                const userId = req.params.id;
                db.query("SELECT * FROM users WHERE id = ?", [userId]);
            `,
            shouldFind: false,
        },
        {
            name: "Template literal injection",
            code: `
                db.query(\`SELECT * FROM users WHERE name = '\${req.body.name}'\`);
            `,
            shouldFind: true,
            severity:   "critical",
        },
    }

    scanner := NewTestScanner()

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            findings := scanner.ScanCode(tc.code, "javascript")

            if tc.shouldFind {
                assert.NotEmpty(t, findings, "Expected to find vulnerability")
                assert.Equal(t, tc.severity, findings[0].Severity)
            } else {
                assert.Empty(t, findings, "Expected no findings for safe code")
            }
        })
    }
}
```

### 5.2 Benchmark Against Competitors

```bash
#!/bin/bash
# scripts/benchmark.sh

# Run your scanner
echo "Running SecureCode Scanner..."
time ./scanner -path ./testdata/vulnerable -output json > results_ours.json

# Run Semgrep
echo "Running Semgrep..."
time semgrep --config=auto ./testdata/vulnerable --json > results_semgrep.json

# Run comparison
python scripts/compare_results.py results_ours.json results_semgrep.json
```

```python
# scripts/compare_results.py
import json
import sys

def compare_results(ours_file, theirs_file):
    with open(ours_file) as f:
        ours = json.load(f)
    with open(theirs_file) as f:
        theirs = json.load(f)

    # Compare findings
    our_findings = set((f['ruleId'], f['path'], f['line']) for f in ours['findings'])
    their_findings = set((f['check_id'], f['path'], f['start']['line'])
                         for f in theirs['results'])

    # Calculate metrics
    true_positives = our_findings & their_findings
    our_unique = our_findings - their_findings
    their_unique = their_findings - our_findings

    print(f"Common findings: {len(true_positives)}")
    print(f"Our unique findings: {len(our_unique)}")
    print(f"Their unique findings: {len(their_unique)}")
    print(f"Our total: {len(our_findings)}")
    print(f"Their total: {len(their_findings)}")

    # Calculate precision/recall if you have ground truth
    # ...
```

---

## Part 6: Performance Optimization

### 6.1 Parallel Scanning

```go
func (s *Scanner) ScanParallel(paths []string) ([]*models.Finding, error) {
    numWorkers := runtime.NumCPU()
    jobs := make(chan string, len(paths))
    results := make(chan []*models.Finding, len(paths))

    // Start workers
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for path := range jobs {
                findings := s.scanFile(path)
                results <- findings
            }
        }()
    }

    // Send jobs
    go func() {
        for _, path := range paths {
            jobs <- path
        }
        close(jobs)
    }()

    // Collect results
    go func() {
        wg.Wait()
        close(results)
    }()

    allFindings := []*models.Finding{}
    for findings := range results {
        allFindings = append(allFindings, findings...)
    }

    return allFindings, nil
}
```

### 6.2 Caching

```go
type CachedParser struct {
    parser *parser.Parser
    cache  *lru.Cache
}

func (cp *CachedParser) ParseFile(path string) (*sitter.Tree, error) {
    // Check cache
    fileInfo, _ := os.Stat(path)
    cacheKey := fmt.Sprintf("%s:%d", path, fileInfo.ModTime().Unix())

    if tree, ok := cp.cache.Get(cacheKey); ok {
        return tree.(*sitter.Tree), nil
    }

    // Parse
    tree, err := cp.parser.ParseFile(path, detectLanguage(path))
    if err != nil {
        return nil, err
    }

    // Cache
    cp.cache.Add(cacheKey, tree)

    return tree, nil
}
```

---

## Part 7: Deployment

### 7.1 GitHub Action

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Run SecureCode Scanner
        uses: yourorg/securecode-action@v1
        with:
          path: .
          severity: high,critical
          fail-on-findings: true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### 7.2 Docker Container

```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o scanner ./cmd/scanner

FROM alpine:latest
RUN apk --no-cache add ca-certificates

WORKDIR /root/
COPY --from=builder /app/scanner .
COPY --from=builder /app/rules ./rules

ENTRYPOINT ["./scanner"]
```

---

## Part 8: Metrics & Monitoring

### 8.1 Telemetry

```go
type Metrics struct {
    FilesScanned     int
    FindingsCount    int
    ScanDuration     time.Duration
    ByLanguage       map[string]int
    BySeverity       map[string]int
    FalsePositiveRate float64
}

func (s *Scanner) CollectMetrics() *Metrics {
    return &Metrics{
        FilesScanned:  s.filesScanned,
        FindingsCount: len(s.findings),
        ScanDuration:  time.Since(s.startTime),
        ByLanguage:    s.countByLanguage(),
        BySeverity:    s.countBySeverity(),
    }
}
```

---

## Next Steps Checklist

### Week 1
- [ ] Set up Go project structure
- [ ] Integrate Tree-sitter
- [ ] Parse first file successfully
- [ ] Write basic tree traversal

### Week 2
- [ ] Implement rule loader (YAML)
- [ ] Convert 5 MD files to rules
- [ ] Implement pattern matching
- [ ] Test on vulnerable code samples

### Week 3
- [ ] Build CLI interface
- [ ] Add JSON/SARIF output
- [ ] Implement parallel scanning
- [ ] Add file caching

### Week 4
- [ ] Integrate LLM for validation
- [ ] Generate auto-fixes
- [ ] Build HTML reporter
- [ ] Create GitHub Action

### Month 2
- [ ] Add 5 more languages
- [ ] Implement taint analysis
- [ ] Add 100+ rules
- [ ] Performance optimization
- [ ] Beta testing with 5 companies

---

## Resources

### Learning Tree-sitter
- https://tree-sitter.github.io/tree-sitter/
- https://github.com/smacker/go-tree-sitter
- Tree-sitter playground: https://tree-sitter.github.io/tree-sitter/playground

### AST Patterns
- Semgrep pattern syntax: https://semgrep.dev/docs/writing-rules/pattern-syntax/
- CodeQL queries: https://codeql.github.com/docs/writing-codeql-queries/

### SARIF Format
- https://sarifweb.azurewebsites.net/
- https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

### Go Libraries
- Tree-sitter: `github.com/smacker/go-tree-sitter`
- CLI: `github.com/spf13/cobra`
- YAML: `gopkg.in/yaml.v3`
- OpenAI: `github.com/sashabaranov/go-openai`

---

**Start building now!** The first working prototype can be done in 2 weeks if you focus.
