# AI Action

[![Go Version](https://img.shields.io/badge/Go-1.25-blue.svg)](https://golang.org/dl/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![GitHub Actions](https://img.shields.io/badge/GitHub-Actions-blue)](https://github.com/features/actions)

A flexible GitHub Action that leverages AWS Bedrock (Claude AI) to perform **any** AI-powered code analysis task using custom prompts.

## 🚀 Features

- **🎯 Fully Customizable**: Provide your own prompts for any AI task
- **🔒 Security Scanning**: Detect vulnerabilities, secrets, and security issues
- **📊 Code Quality Analysis**: Review code quality, complexity, and maintainability
- **📝 Documentation Generation**: Auto-generate comprehensive documentation
- **🧪 Test Generation**: Create unit tests, integration tests, and test plans
- **♻️ Refactoring Suggestions**: Identify code smells and improvement opportunities
- **⚡ Performance Analysis**: Find bottlenecks and optimization opportunities
- **🤖 Powered by Claude 3.5 Sonnet**: State-of-the-art AI model via AWS Bedrock
- **✅ Input Validation**: Comprehensive security validation for all inputs
- **💬 PR Comments**: Automatically post analysis results as PR comments

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Usage](#usage)
- [Examples](#examples)
- [Configuration](#configuration)
- [Use Cases](#use-cases)
- [Environment Variables](#environment-variables)
- [Development](#development)
- [Contributing](#contributing)

## ⚡ Quick Start

### Prerequisites

- GitHub repository
- AWS account with Bedrock access
- GitHub App with repository read permissions

### Basic Usage

Add to your `.github/workflows/ai-analysis.yml`:

```yaml
name: AI Code Analysis
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - name: AI Analysis
        uses: your-org/ai-action@v1
        with:
          prompt: "Analyze this code for security vulnerabilities and rate their severity"
          owner: ${{ github.repository_owner }}
          repo: ${{ github.event.repository.name }}
          pr-number: ${{ github.event.pull_request.number }}
        env:
          GH_APP_PRIVATE_KEY: ${{ secrets.GH_APP_PRIVATE_KEY }}
          GH_APP_ID: ${{ secrets.GH_APP_ID }}
          GH_APP_INSTALLATION_ID: ${{ secrets.GH_APP_INSTALLATION_ID }}
          AWS_REGION: ${{ secrets.AWS_REGION }}
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

## 🎯 Usage

### Command Line

```bash
# Generic analysis with custom prompt
ai-action analyze \
  --owner myorg \
  --repo myrepo \
  --prompt "Your custom AI prompt here" \
  --pr-number 123

# With specific file paths
ai-action analyze \
  --owner myorg \
  --repo myrepo \
  --paths "*.go,*.js" \
  --prompt "Review these files for code quality" \
  --max-files 50

# With git reference
ai-action analyze \
  --owner myorg \
  --repo myrepo \
  --ref feature-branch \
  --prompt "Analyze changes in this branch"
```

### Flags

| Flag | Short | Required | Default | Description |
|------|-------|----------|---------|-------------|
| `--owner` | `-o` | Yes | - | GitHub repository owner |
| `--repo` | `-r` | Yes | - | GitHub repository name |
| `--prompt` | `-p` | Yes | - | AI analysis prompt (your custom instructions) |
| `--ref` | - | No | main | Git reference (branch, tag, or commit SHA) |
| `--paths` | - | No | all | Comma-separated file patterns (e.g., '*.go,*.js') |
| `--max-files` | `-m` | No | 20 | Maximum number of files to analyze |
| `--pr-number` | - | No | 0 | PR number to post results as comment |
| `--output` | - | No | text | Output format: text or json |

## 💡 Examples

### 1. Security Vulnerability Scanning

```yaml
- name: Security Scan
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Scan for security vulnerabilities including:
      - SQL injection
      - XSS vulnerabilities
      - Hardcoded secrets or credentials
      - Insecure cryptography
      - Command injection
      Rate each finding by severity (Critical, High, Medium, Low)
```

### 2. Documentation Generation

```yaml
- name: Generate Documentation
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Generate comprehensive API documentation including:
      - Function descriptions
      - Parameter documentation
      - Return value descriptions
      - Usage examples
      - Edge cases and error handling
```

### 3. Test Generation

```yaml
- name: Generate Tests
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Generate unit tests for all functions including:
      - Happy path test cases
      - Edge cases
      - Error handling
      - Mock setup where needed
      Use the existing test framework in the codebase
```

### 4. Code Review

```yaml
- name: AI Code Review
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Review code quality focusing on:
      - Design patterns and best practices
      - Code complexity and maintainability
      - Error handling
      - Performance considerations
      - Naming conventions
      Provide specific suggestions for improvement
```

### 5. Performance Analysis

```yaml
- name: Performance Analysis
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Identify performance bottlenecks including:
      - Inefficient algorithms (time complexity)
      - Memory leaks or excessive allocations
      - Database query optimization opportunities
      - Unnecessary API calls or network requests
      Suggest specific optimizations
```

### 6. Refactoring Suggestions

```yaml
- name: Refactoring Opportunities
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Identify refactoring opportunities:
      - Code duplication (DRY violations)
      - Long functions that should be split
      - God objects or classes with too many responsibilities
      - Poor separation of concerns
      - Opportunities to use design patterns
```

### 7. Architecture Review

```yaml
- name: Architecture Review
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Review system architecture:
      - Evaluate component boundaries and separation
      - Identify tight coupling
      - Check adherence to SOLID principles
      - Suggest architectural improvements
      - Assess scalability concerns
```

### 8. Accessibility Analysis

```yaml
- name: Accessibility Check
  uses: your-org/ai-action@v1
  with:
    prompt: |
      Analyze frontend code for accessibility:
      - ARIA labels and semantic HTML
      - Keyboard navigation support
      - Screen reader compatibility
      - Color contrast and visual accessibility
      - WCAG 2.1 compliance
```

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GH_APP_PRIVATE_KEY` | Yes | GitHub App private key (PEM format) |
| `GH_APP_ID` | Yes | GitHub App ID |
| `GH_APP_INSTALLATION_ID` | Yes | GitHub App installation ID |
| `AWS_REGION` | Yes | AWS region (e.g., us-east-1) |
| `AWS_ACCESS_KEY_ID` | Yes | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Yes | AWS secret key |

### GitHub App Setup

1. Create a GitHub App with these permissions:
   - **Repository permissions**:
     - Contents: Read
     - Pull requests: Read & Write (for PR comments)
   - **Subscribe to events**: Pull request

2. Generate and download the private key

3. Install the app on your repositories

4. Add secrets to your GitHub repository settings

### AWS Bedrock Setup

1. Enable AWS Bedrock in your AWS account
2. Request access to Claude 3.5 Sonnet model
3. Create IAM user with bedrock:InvokeModel permission
4. Add AWS credentials to GitHub secrets

## 🎨 Use Cases

### Development Workflow

- **Pre-merge checks**: Run AI analysis on every PR
- **Scheduled scans**: Weekly security and quality audits
- **Release preparation**: Comprehensive analysis before releases
- **Onboarding**: Generate documentation for new team members

### Specific Tasks

- **Security**: Find vulnerabilities, hardcoded secrets, injection risks
- **Quality**: Check code complexity, maintainability, best practices
- **Testing**: Generate test cases, identify coverage gaps
- **Documentation**: Auto-generate API docs, README sections, comments
- **Performance**: Identify slow queries, memory leaks, algorithm issues
- **Refactoring**: Find code smells, duplication, design pattern opportunities
- **Compliance**: Check coding standards, license compliance, regulatory requirements
- **Accessibility**: WCAG compliance, semantic HTML, ARIA labels

## 🛠️ Development

### Building from Source

```bash
# Clone the repository
git clone https://github.com/your-org/ai-action.git
cd ai-action

# Install dependencies
go mod download

# Build
go build -v

# Run
./ai-action analyze --owner myorg --repo myrepo --prompt "Your prompt"
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Docker Build

```bash
# Build Docker image
docker build -t ai-action:latest .

# Run in Docker
docker run --rm \
  -e GH_APP_PRIVATE_KEY="..." \
  -e GH_APP_ID="..." \
  -e GH_APP_INSTALLATION_ID="..." \
  -e AWS_REGION="..." \
  -e AWS_ACCESS_KEY_ID="..." \
  -e AWS_SECRET_ACCESS_KEY="..." \
  ai-action:latest analyze --owner myorg --repo myrepo --prompt "Your prompt"
```

## 🔒 Security

### Input Validation

All inputs are validated and sanitized:
- ✅ GitHub owner/repo name validation
- ✅ Git reference validation
- ✅ Path traversal prevention
- ✅ Special character filtering
- ✅ Length limits enforcement
- ✅ Null byte removal

### Best Practices

- Store secrets in GitHub Secrets, never in code
- Use least-privilege IAM policies for AWS
- Limit file analysis with `--max-files` flag
- Review AI-generated suggestions before applying
- Use specific file paths with `--paths` for targeted analysis

## 📊 Output Formats

### Text Output (Default)

```
🤖 Starting AI analysis for myorg/myrepo
📍 Reference: main
💬 Prompt: Scan for security vulnerabilities

📁 Fetching repository files...
📊 Found 15 files to analyze

🤖 Initializing AI handler...
🔬 Performing AI analysis...

================================================================================
🤖 AI Analysis Results for myorg/myrepo
================================================================================
[AI-generated analysis appears here]
================================================================================

✅ Successfully posted analysis results to PR #123
```

### JSON Output

```bash
ai-action analyze --output json --owner myorg --repo myrepo --prompt "Analyze code"
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with [AWS Bedrock](https://aws.amazon.com/bedrock/) and Claude 3.5 Sonnet
- Uses [LangChain Go](https://github.com/tmc/langchaingo) for AI orchestration
- Powered by [Cobra](https://github.com/spf13/cobra) CLI framework

## 📞 Support

- 📧 Email: support@your-org.com
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/ai-action/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/your-org/ai-action/discussions)

---

**Made with ❤️ for developers who want AI-powered code analysis**
