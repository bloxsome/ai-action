package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/rs/zerolog/log"
	"github.com/tmc/langchaingo/chains"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/bedrock"
	"github.com/tmc/langchaingo/schema"

	claudeclient "ai-action/utils/claude-client"
)

// AIHandler provides methods to interact with AI models using langchain
type AIHandler struct {
	bedrockClient *bedrockruntime.Client
	llm           *bedrock.LLM
}

// NewAIHandler creates a new AIHandler with initialized clients
func NewAIHandler() (*AIHandler, error) {
	// Initialize Bedrock client
	bedrockClient, err := claudeclient.GetClaudeClient()
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize Bedrock client")
		return nil, fmt.Errorf("failed to initialize Bedrock client: %w", err)
	}

	// Initialize LLM client
	llm, err := claudeclient.GetLLMClient(bedrockClient)
	if err != nil {
		log.Error().Err(err).Msg("Failed to initialize LLM client")
		return nil, fmt.Errorf("failed to initialize LLM client: %w", err)
	}

	return &AIHandler{
		bedrockClient: bedrockClient,
		llm:           llm,
	}, nil
}

// Call makes a simple call to the AI model with the given prompt
func (ah *AIHandler) Call(ctx context.Context, prompt string) (string, error) {
	log.Debug().Str("prompt", prompt).Msg("Making AI call")

	response, err := ah.llm.Call(ctx, prompt)
	if err != nil {
		log.Error().Err(err).Str("prompt", prompt).Msg("Failed to call AI model")
		return "", fmt.Errorf("failed to call AI model: %w", err)
	}

	log.Debug().Str("response", response).Msg("Received AI response")
	return response, nil
}

// CallWithOptions makes a call to the AI model with additional options
func (ah *AIHandler) CallWithOptions(ctx context.Context, prompt string, options ...llms.CallOption) (string, error) {
	log.Debug().Str("prompt", prompt).Msg("Making AI call with options")

	response, err := ah.llm.Call(ctx, prompt, options...)
	if err != nil {
		log.Error().Err(err).Str("prompt", prompt).Msg("Failed to call AI model with options")
		return "", fmt.Errorf("failed to call AI model with options: %w", err)
	}

	log.Debug().Str("response", response).Msg("Received AI response")
	return response, nil
}

// GenerateContent generates content based on a prompt with streaming support
func (ah *AIHandler) GenerateContent(ctx context.Context, prompt string, callback func(string)) error {
	log.Debug().Str("prompt", prompt).Msg("Generating content with streaming")

	_, err := ah.llm.GenerateContent(ctx, []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeHuman, prompt),
	}, llms.WithStreamingFunc(func(ctx context.Context, chunk []byte) error {
		content := string(chunk)
		if callback != nil {
			callback(content)
		}
		return nil
	}))

	if err != nil {
		log.Error().Err(err).Str("prompt", prompt).Msg("Failed to generate content")
		return fmt.Errorf("failed to generate content: %w", err)
	}

	return nil
}

// AnalyzeCode analyzes code and provides insights
func (ah *AIHandler) AnalyzeCode(ctx context.Context, code string, analysisType string) (string, error) {
	prompt := fmt.Sprintf("Please analyze the following %s code and provide insights:\n\n%s", analysisType, code)

	log.Debug().
		Str("analysis_type", analysisType).
		Int("code_length", len(code)).
		Msg("Analyzing code")

	return ah.Call(ctx, prompt)
}

// ReviewCode reviews code for security, quality, and best practices
func (ah *AIHandler) ReviewCode(ctx context.Context, code string, language string) (string, error) {
	prompt := fmt.Sprintf(`Please review the following %s code for:
1. Security vulnerabilities
2. Code quality issues
3. Best practices compliance
4. Performance considerations

Code:
%s

Please provide specific recommendations for improvement.`, language, code)

	log.Info().
		Str("language", language).
		Int("code_length", len(code)).
		Msg("Reviewing code")

	return ah.Call(ctx, prompt)
}

// ExplainCode explains what a piece of code does
func (ah *AIHandler) ExplainCode(ctx context.Context, code string, language string) (string, error) {
	prompt := fmt.Sprintf("Please explain what this %s code does in clear, simple terms:\n\n%s", language, code)

	log.Info().
		Str("language", language).
		Int("code_length", len(code)).
		Msg("Explaining code")

	return ah.Call(ctx, prompt)
}

// FileContext represents a file with its content for context
type FileContext struct {
	Path     string
	Content  string
	Language string
}

// AnalyzeMultipleFiles analyzes multiple files together with shared context
func (ah *AIHandler) AnalyzeMultipleFiles(ctx context.Context, files []FileContext, question string) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no files provided for analysis")
	}

	// Create documents from file contexts
	docs := make([]schema.Document, len(files))
	for i, file := range files {
		metadata := map[string]any{
			"path":     file.Path,
			"language": file.Language,
		}
		docs[i] = schema.Document{
			PageContent: fmt.Sprintf("File: %s\nLanguage: %s\nContent:\n%s", file.Path, file.Language, file.Content),
			Metadata:    metadata,
		}
	}

	log.Debug().
		Int("file_count", len(files)).
		Str("question", question).
		Msg("Analyzing multiple files with context")

	// Use stuff QA chain to load all documents into a single prompt
	stuffQAChain := chains.LoadStuffQA(ah.llm)
	result, err := chains.Call(ctx, stuffQAChain, map[string]any{
		"input_documents": docs,
		"question":        question,
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to analyze multiple files")
		return "", fmt.Errorf("failed to analyze multiple files: %w", err)
	}

	answer, ok := result["text"].(string)
	if !ok {
		return "", fmt.Errorf("unexpected response format from QA chain")
	}

	log.Debug().Str("answer", answer).Msg("Received analysis for multiple files")
	return answer, nil
}

// ReviewMultipleFiles reviews multiple files together for security and quality
func (ah *AIHandler) ReviewMultipleFiles(ctx context.Context, files []FileContext) (string, error) {
	question := `Please review these files for:
1. Security vulnerabilities across the codebase
2. Code quality issues and inconsistencies
3. Best practices compliance
4. Cross-file dependencies and potential issues
5. Architecture and design patterns

Provide specific recommendations for improvement and highlight any critical issues.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// ExplainCodebaseStructure explains the structure and relationships between multiple files
func (ah *AIHandler) ExplainCodebaseStructure(ctx context.Context, files []FileContext) (string, error) {
	question := `Please explain the structure and relationships of this codebase:
1. What is the overall architecture and purpose?
2. How do the files relate to each other?
3. What are the main components and their responsibilities?
4. What patterns and frameworks are being used?
5. What is the data flow between components?

Provide a clear, high-level explanation suitable for someone new to the codebase.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// FindSecurityIssuesAcrossFiles identifies security issues that span multiple files
func (ah *AIHandler) FindSecurityIssuesAcrossFiles(ctx context.Context, files []FileContext) (string, error) {
	question := `Focus specifically on security analysis across these files:
1. Look for authentication and authorization issues
2. Identify potential injection vulnerabilities (SQL, XSS, etc.)
3. Check for insecure data handling and storage
4. Review error handling and information disclosure
5. Examine cross-file security patterns and inconsistencies
6. Look for hardcoded secrets or credentials
7. Check for insecure communication patterns

Prioritize findings by severity and provide specific remediation steps.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// ScanForSecrets identifies potential secrets, API keys, and credentials in code
func (ah *AIHandler) ScanForSecrets(ctx context.Context, files []FileContext) (string, error) {
	question := `Scan these files specifically for hardcoded secrets and credentials:
1. API keys, tokens, and authentication credentials
2. Database connection strings and passwords
3. Private keys and certificates
4. OAuth secrets and client credentials
5. Cloud service credentials (AWS, GCP, Azure keys)
6. Third-party service tokens
7. Encryption keys and salts
8. Environment-specific secrets that shouldn't be in code

Flag any suspicious patterns even if they might be fake/placeholder values. 
Provide specific line references and remediation advice for each finding.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// AnalyzeDataFlow examines how sensitive data flows through the application
func (ah *AIHandler) AnalyzeDataFlow(ctx context.Context, files []FileContext) (string, error) {
	question := `Analyze the data flow security in this codebase:
1. How is sensitive data (PII, passwords, tokens) handled?
2. Are there proper input validation and sanitization mechanisms?
3. How is data transmitted between components/services?
4. What data is logged and could expose sensitive information?
5. Are there proper data encryption/decryption practices?
6. How is data stored and is it properly protected?
7. Are there data leakage points in error messages or responses?

Map the flow of sensitive data and identify security gaps.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// CheckAuthenticationSecurity focuses on authentication and authorization mechanisms
func (ah *AIHandler) CheckAuthenticationSecurity(ctx context.Context, files []FileContext) (string, error) {
	question := `Analyze authentication and authorization security:
1. How are users authenticated (login mechanisms, multi-factor auth)?
2. Are passwords properly hashed and stored securely?
3. How are sessions managed and secured?
4. Are there proper authorization checks for different operations?
5. How are JWT tokens or API keys validated?
6. Are there privilege escalation vulnerabilities?
7. How is access control implemented across the application?
8. Are there insecure direct object references?

Focus specifically on auth-related security vulnerabilities and weaknesses.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// ScanForInjectionVulnerabilities looks for various injection attack vectors
func (ah *AIHandler) ScanForInjectionVulnerabilities(ctx context.Context, files []FileContext) (string, error) {
	question := `Scan for injection vulnerabilities across these files:
1. SQL injection in database queries and ORM usage
2. Cross-site scripting (XSS) in web outputs and templates  
3. Command injection in system calls and shell executions
4. LDAP injection in directory service queries
5. XML/XXE injection in XML parsing
6. NoSQL injection in document database queries
7. Template injection in rendering engines
8. Code injection in dynamic code execution

Examine user input handling, query construction, and output encoding.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// AnalyzeCryptographicSecurity examines cryptographic implementations
func (ah *AIHandler) AnalyzeCryptographicSecurity(ctx context.Context, files []FileContext) (string, error) {
	question := `Analyze cryptographic security implementation:
1. Are strong, up-to-date encryption algorithms being used?
2. Is key generation, storage, and rotation handled securely?
3. Are there weak hashing algorithms (MD5, SHA1) being used?
4. How are random numbers generated for cryptographic purposes?
5. Are there proper certificate validation and TLS configurations?
6. How are sensitive operations like signing and encryption implemented?
7. Are there timing attack vulnerabilities in crypto operations?
8. Is there proper handling of cryptographic errors and exceptions?

Focus on cryptographic best practices and common implementation flaws.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// CheckDependencySecurity analyzes third-party dependencies for security issues
func (ah *AIHandler) CheckDependencySecurity(ctx context.Context, files []FileContext) (string, error) {
	question := `Analyze dependency and supply chain security:
1. What third-party libraries and frameworks are being used?
2. Are there any known vulnerable dependencies?
3. How are dependencies managed and updated?
4. Are there unnecessary or overprivileged dependencies?
5. How are package integrity and authenticity verified?
6. Are there any suspicious or untrusted dependencies?
7. What is the attack surface exposed by external dependencies?
8. Are there proper dependency pinning and lock file practices?

Examine import statements, package files, and dependency configurations.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// ScanForBusinessLogicFlaws identifies application-specific security issues
func (ah *AIHandler) ScanForBusinessLogicFlaws(ctx context.Context, files []FileContext) (string, error) {
	question := `Analyze business logic security flaws:
1. Are there race conditions in critical operations?
2. Can business rules be bypassed or manipulated?
3. Are there improper state transitions or workflow bypasses?
4. How are rate limiting and abuse prevention implemented?
5. Are there pricing, payment, or financial calculation vulnerabilities?
6. How are user permissions and roles enforced in business operations?
7. Are there time-based security issues (TOCTOU vulnerabilities)?
8. Can users manipulate business processes in unintended ways?

Focus on application-specific logic that could be exploited.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// AnalyzeSecurityHeaders examines HTTP security configurations
func (ah *AIHandler) AnalyzeSecurityHeaders(ctx context.Context, files []FileContext) (string, error) {
	question := `Analyze HTTP security and web application security:
1. What security headers are being set (CSP, HSTS, X-Frame-Options, etc.)?
2. How is CORS configured and are there overly permissive policies?
3. Are there proper CSRF protection mechanisms?
4. How are cookies secured (HttpOnly, Secure, SameSite flags)?
5. Is there proper input validation and output encoding for web inputs?
6. How are file uploads handled and validated?
7. Are there clickjacking protections in place?
8. How is content type handling implemented?

Focus on web security configurations and HTTP-related vulnerabilities.`

	return ah.AnalyzeMultipleFiles(ctx, files, question)
}

// RefineAnalysisWithContext uses refine QA chain for iterative analysis across files
func (ah *AIHandler) RefineAnalysisWithContext(ctx context.Context, files []FileContext, question string) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no files provided for analysis")
	}

	// Create documents from file contexts
	docs := make([]schema.Document, len(files))
	for i, file := range files {
		metadata := map[string]any{
			"path":     file.Path,
			"language": file.Language,
		}
		docs[i] = schema.Document{
			PageContent: fmt.Sprintf("File: %s\nLanguage: %s\nContent:\n%s", file.Path, file.Language, file.Content),
			Metadata:    metadata,
		}
	}

	log.Debug().
		Int("file_count", len(files)).
		Str("question", question).
		Msg("Refining analysis across multiple files")

	// Use refine QA chain for iterative processing
	refineQAChain := chains.LoadRefineQA(ah.llm)
	result, err := chains.Call(ctx, refineQAChain, map[string]any{
		"input_documents": docs,
		"question":        question,
	})

	if err != nil {
		log.Error().Err(err).Msg("Failed to refine analysis across files")
		return "", fmt.Errorf("failed to refine analysis: %w", err)
	}

	answer, ok := result["text"].(string)
	if !ok {
		return "", fmt.Errorf("unexpected response format from refine QA chain")
	}

	log.Debug().Str("answer", answer).Msg("Received refined analysis")
	return answer, nil
}

// CreateFileContextFromContent creates FileContext from file path and content
func CreateFileContextFromContent(path, content string) FileContext {
	// Infer language from file extension
	language := inferLanguageFromPath(path)

	return FileContext{
		Path:     path,
		Content:  content,
		Language: language,
	}
}

// CalculateSeverityScore analyzes text describing changes and returns a severity score (1-10)
// Returns the numeric score, the AI response explanation, and any error encountered
func (ah *AIHandler) CalculateSeverityScore(ctx context.Context, changeDescription string) (score int, response string, err error) {
	prompt := fmt.Sprintf(`Analyze the following change description and assign a severity score from 1-10 based on the potential security and operational impact:

1-2: Low severity (minor changes, cosmetic updates, documentation)
3-4: Low-medium severity (small feature additions, minor bug fixes)
5-6: Medium severity (significant feature changes, configuration updates, dependency changes)
7-8: High severity (security-related changes, authentication/authorization modifications, data handling changes)
9-10: Critical severity (major security vulnerabilities, breaking changes, system-wide impacts)

Change description: %s

Please respond with only the numeric severity score (1-10) followed by a brief explanation on the next line.`, changeDescription)

	response, err = ah.Call(ctx, prompt)
	if err != nil {
		log.Error().Err(err).Str("change_description", changeDescription).Msg("Failed to calculate severity score")
		return 0, "", fmt.Errorf("failed to calculate severity score: %w", err)
	}

	// Parse the numeric score from the response
	lines := strings.Split(strings.TrimSpace(response), "\n")
	if len(lines) == 0 {
		return 0, "", fmt.Errorf("empty response from AI model")
	}

	scoreStr := strings.TrimSpace(lines[0])
	score = 0

	// Try to extract numeric score from the first line
	for i, char := range scoreStr {
		if char >= '0' && char <= '9' {
			if i+1 < len(scoreStr) && scoreStr[i+1] >= '0' && scoreStr[i+1] <= '9' {
				// Two digit number
				if scoreStr[i:i+2] == "10" {
					score = 10
					break
				}
			}
			// Single digit
			score = int(char - '0')
			break
		}
	}

	// Validate score range
	if score < 1 || score > 10 {
		log.Warn().Int("parsed_score", score).Str("response", response).Msg("Invalid severity score, defaulting to 5")
		score = 5 // Default to medium severity if parsing fails
	}

	log.Debug().
		Int("severity_score", score).
		Str("ai_response", response).
		Msg("Calculated severity score")

	return score, response, nil
}

// inferLanguageFromPath infers programming language from file path
func inferLanguageFromPath(path string) string {
	// Get the base filename
	filename := path
	if strings.Contains(path, "/") {
		filename = path[strings.LastIndex(path, "/")+1:]
	}

	// Check for special filenames without extensions
	switch strings.ToLower(filename) {
	case "dockerfile", "dockerfile.dev", "dockerfile.prod":
		return "Dockerfile"
	case "makefile":
		return "Makefile"
	case "rakefile":
		return "Ruby"
	}

	// Check for file extensions
	if strings.Contains(filename, ".") {
		ext := filename[strings.LastIndex(filename, "."):]
		switch ext {
		case ".go":
			return "Go"
		case ".js", ".mjs":
			return "JavaScript"
		case ".ts":
			return "TypeScript"
		case ".py":
			return "Python"
		case ".java":
			return "Java"
		case ".cpp", ".cc", ".cxx":
			return "C++"
		case ".c":
			return "C"
		case ".rs":
			return "Rust"
		case ".rb":
			return "Ruby"
		case ".php":
			return "PHP"
		case ".cs":
			return "C#"
		case ".kt":
			return "Kotlin"
		case ".swift":
			return "Swift"
		case ".scala":
			return "Scala"
		case ".sql":
			return "SQL"
		case ".yaml", ".yml":
			return "YAML"
		case ".json":
			return "JSON"
		case ".xml":
			return "XML"
		case ".html":
			return "HTML"
		case ".css":
			return "CSS"
		case ".sh":
			return "Shell"
		case ".dockerfile":
			return "Dockerfile"
		default:
			return "Unknown"
		}
	}
	return "Unknown"
}
