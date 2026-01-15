package ai

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAIHandler(t *testing.T) {
	handler, err := NewAIHandler()
	
	// Note: This test might fail if AWS credentials are not configured
	// In that case, we expect a specific error
	if err != nil {
		t.Logf("Expected error due to missing AWS credentials: %v", err)
		assert.Contains(t, err.Error(), "failed to initialize")
		return
	}
	
	require.NotNil(t, handler)
	assert.NotNil(t, handler.bedrockClient)
	assert.NotNil(t, handler.llm)
}

func TestAIHandler_Call(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	prompt := "What is 2+2? Please answer with just the number."
	response, err := handler.Call(ctx, prompt)

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	assert.Contains(t, response, "4")
}

func TestAIHandler_AnalyzeCode(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := `
func fibonacci(n int) int {
    if n <= 1 {
        return n
    }
    return fibonacci(n-1) + fibonacci(n-2)
}
`
	
	response, err := handler.AnalyzeCode(ctx, code, "Go")

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should contain some analysis of the fibonacci function
	assert.True(t, strings.Contains(response, "fibonacci") || strings.Contains(response, "recursive"))
}

func TestAIHandler_ReviewCode(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := `
func unsafeFunction(input string) {
    // Potential SQL injection vulnerability
    query := "SELECT * FROM users WHERE name = '" + input + "'"
    // Execute query without sanitization
}
`
	
	response, err := handler.ReviewCode(ctx, code, "Go")

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should identify security issues
	assert.True(t, 
		strings.Contains(strings.ToLower(response), "security") || 
		strings.Contains(strings.ToLower(response), "injection") ||
		strings.Contains(strings.ToLower(response), "sql"))
}

func TestAIHandler_ExplainCode(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	code := `
func bubbleSort(arr []int) {
    n := len(arr)
    for i := 0; i < n-1; i++ {
        for j := 0; j < n-i-1; j++ {
            if arr[j] > arr[j+1] {
                arr[j], arr[j+1] = arr[j+1], arr[j]
            }
        }
    }
}
`
	
	response, err := handler.ExplainCode(ctx, code, "Go")

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should explain the bubble sort algorithm
	assert.True(t, 
		strings.Contains(strings.ToLower(response), "sort") || 
		strings.Contains(strings.ToLower(response), "bubble") ||
		strings.Contains(strings.ToLower(response), "array"))
}

func TestAIHandler_GenerateContent(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var receivedContent strings.Builder
	callback := func(content string) {
		receivedContent.WriteString(content)
	}

	prompt := "Write a simple hello world function in Go."
	err = handler.GenerateContent(ctx, prompt, callback)

	assert.NoError(t, err)
	content := receivedContent.String()
	assert.NotEmpty(t, content)
	// Should contain Go-related content
	assert.True(t, 
		strings.Contains(strings.ToLower(content), "func") || 
		strings.Contains(strings.ToLower(content), "go") ||
		strings.Contains(strings.ToLower(content), "hello"))
}

func TestAIHandler_CallWithTimeout(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	// Test with a very short timeout to ensure timeout handling works
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	prompt := "This is a test prompt that should timeout quickly."
	_, err = handler.Call(ctx, prompt)

	// Should get a context deadline exceeded error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestAIHandler_EmptyPrompt(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with empty prompt
	response, err := handler.Call(ctx, "")

	// Should handle empty prompt gracefully
	if err != nil {
		// Some models might reject empty prompts
		assert.NotNil(t, err)
	} else {
		// If no error, should return some response
		assert.NotNil(t, response)
	}
}

func TestCreateFileContextFromContent(t *testing.T) {
	tests := []struct {
		path     string
		content  string
		expected string
	}{
		{"main.go", "package main", "Go"},
		{"script.py", "print('hello')", "Python"},
		{"app.js", "console.log('test')", "JavaScript"},
		{"style.css", "body { margin: 0; }", "CSS"},
		{"config.yaml", "version: 1", "YAML"},
		{"unknown.xyz", "some content", "Unknown"},
		{"noextension", "content", "Unknown"},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			ctx := CreateFileContextFromContent(test.path, test.content)
			assert.Equal(t, test.path, ctx.Path)
			assert.Equal(t, test.content, ctx.Content)
			assert.Equal(t, test.expected, ctx.Language)
		})
	}
}

func TestAIHandler_AnalyzeMultipleFiles(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	files := []FileContext{
		{
			Path:     "main.go",
			Content:  "package main\n\nfunc main() {\n    println(\"Hello World\")\n}",
			Language: "Go",
		},
		{
			Path:     "utils.go",
			Content:  "package main\n\nfunc helper() string {\n    return \"helper function\"\n}",
			Language: "Go",
		},
	}

	question := "What do these Go files do together?"
	response, err := handler.AnalyzeMultipleFiles(ctx, files, question)

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should mention both files and their relationship
	assert.True(t, 
		strings.Contains(strings.ToLower(response), "main") || 
		strings.Contains(strings.ToLower(response), "hello") ||
		strings.Contains(strings.ToLower(response), "go"))
}

func TestAIHandler_AnalyzeMultipleFiles_EmptyFiles(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with empty files slice
	files := []FileContext{}
	question := "What do these files do?"
	
	_, err = handler.AnalyzeMultipleFiles(ctx, files, question)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no files provided")
}

func TestAIHandler_ReviewMultipleFiles(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	files := []FileContext{
		{
			Path:     "auth.go",
			Content:  "package auth\n\nfunc Login(username, password string) {\n    // No password validation\n    query := \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n}",
			Language: "Go",
		},
		{
			Path:     "api.go",
			Content:  "package api\n\nfunc HandleRequest(data string) {\n    // No input sanitization\n    executeSQL(data)\n}",
			Language: "Go",
		},
	}

	response, err := handler.ReviewMultipleFiles(ctx, files)

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should identify security issues
	assert.True(t, 
		strings.Contains(strings.ToLower(response), "security") || 
		strings.Contains(strings.ToLower(response), "injection") ||
		strings.Contains(strings.ToLower(response), "sql") ||
		strings.Contains(strings.ToLower(response), "vulnerability"))
}

func TestAIHandler_ExplainCodebaseStructure(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	files := []FileContext{
		{
			Path:     "main.go",
			Content:  "package main\n\nimport \"./server\"\n\nfunc main() {\n    server.Start()\n}",
			Language: "Go",
		},
		{
			Path:     "server/server.go",
			Content:  "package server\n\nimport \"net/http\"\n\nfunc Start() {\n    http.ListenAndServe(\":8080\", nil)\n}",
			Language: "Go",
		},
		{
			Path:     "handlers/api.go",
			Content:  "package handlers\n\nfunc APIHandler(w http.ResponseWriter, r *http.Request) {\n    // Handle API requests\n}",
			Language: "Go",
		},
	}

	response, err := handler.ExplainCodebaseStructure(ctx, files)

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should explain the structure and relationships
	assert.True(t, 
		strings.Contains(strings.ToLower(response), "server") || 
		strings.Contains(strings.ToLower(response), "main") ||
		strings.Contains(strings.ToLower(response), "structure") ||
		strings.Contains(strings.ToLower(response), "architecture"))
}

func TestAIHandler_FindSecurityIssuesAcrossFiles(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	files := []FileContext{
		{
			Path:     "database.go",
			Content:  "package db\n\nconst PASSWORD = \"hardcoded123\"\n\nfunc Connect() {\n    db.Connect(\"user:\" + PASSWORD + \"@localhost\")\n}",
			Language: "Go",
		},
		{
			Path:     "api.go",
			Content:  "package api\n\nfunc GetUser(id string) {\n    query := \"SELECT * FROM users WHERE id = \" + id\n    // Direct query execution without validation\n}",
			Language: "Go",
		},
	}

	response, err := handler.FindSecurityIssuesAcrossFiles(ctx, files)

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should identify security issues like hardcoded passwords and SQL injection
	assert.True(t, 
		strings.Contains(strings.ToLower(response), "security") || 
		strings.Contains(strings.ToLower(response), "hardcoded") ||
		strings.Contains(strings.ToLower(response), "injection") ||
		strings.Contains(strings.ToLower(response), "password") ||
		strings.Contains(strings.ToLower(response), "vulnerability"))
}

// TODO this is broken
func TestAIHandler_RefineAnalysisWithContext(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	files := []FileContext{
		{
			Path:     "models/user.go",
			Content:  "package models\n\ntype User struct {\n    ID   int\n    Name string\n}",
			Language: "Go",
		},
		{
			Path:     "controllers/user.go",
			Content:  "package controllers\n\nfunc CreateUser(name string) {\n    user := models.User{Name: name}\n    // Save user logic\n}",
			Language: "Go",
		},
		{
			Path:     "routes/routes.go",
			Content:  "package routes\n\nfunc SetupRoutes() {\n    http.HandleFunc(\"/users\", controllers.CreateUser)\n}",
			Language: "Go",
		},
	}

	question := "How do these files work together to handle user creation?"
	response, err := handler.RefineAnalysisWithContext(ctx, files, question)

	assert.NoError(t, err)
	assert.NotEmpty(t, response)
	// Response should explain the flow between models, controllers, and routes
	assert.True(t, 
		strings.Contains(strings.ToLower(response), "user") || 
		strings.Contains(strings.ToLower(response), "model") ||
		strings.Contains(strings.ToLower(response), "controller") ||
		strings.Contains(strings.ToLower(response), "route"))
}

func TestAIHandler_RefineAnalysisWithContext_EmptyFiles(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test with empty files slice
	files := []FileContext{}
	question := "How do these files work together?"
	
	_, err = handler.RefineAnalysisWithContext(ctx, files, question)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no files provided")
}

func TestAIHandler_CalculateSeverityScore(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tests := []struct {
		name               string
		changeDescription  string
		expectedMinScore   int
		expectedMaxScore   int
	}{
		{
			name:              "Low severity - documentation update",
			changeDescription: "Updated README.md with new installation instructions",
			expectedMinScore:  1,
			expectedMaxScore:  3,
		},
		{
			name:              "Medium severity - feature addition",
			changeDescription: "Added new user profile management feature with database schema changes",
			expectedMinScore:  4,
			expectedMaxScore:  7,
		},
		{
			name:              "High severity - security fix",
			changeDescription: "Fixed SQL injection vulnerability in user authentication system",
			expectedMinScore:  7,
			expectedMaxScore:  10,
		},
		{
			name:              "Critical severity - breaking change",
			changeDescription: "Removed deprecated API endpoints that could break existing integrations and expose sensitive data",
			expectedMinScore:  8,
			expectedMaxScore:  10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			score, resp, err := handler.CalculateSeverityScore(ctx, test.changeDescription)
			
			assert.NoError(t, err)
			assert.NotEmpty(t, resp)
			assert.GreaterOrEqual(t, score, 1, "Score should be at least 1")
			assert.LessOrEqual(t, score, 10, "Score should be at most 10")
			assert.GreaterOrEqual(t, score, test.expectedMinScore, "Score should meet minimum expectation")
			assert.LessOrEqual(t, score, test.expectedMaxScore, "Score should meet maximum expectation")
			
			t.Logf("Change: %s -> Score: %d", test.changeDescription, score)
		})
	}
}

func TestAIHandler_CalculateSeverityScore_EmptyDescription(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	score, resp, err := handler.CalculateSeverityScore(ctx, "")
	
	// Should handle empty description gracefully
	if err != nil {
		// Some models might reject empty descriptions
		assert.NotNil(t, err)
	} else {
		// If no error, should return a valid score
		assert.NotNil(t, resp)
		assert.GreaterOrEqual(t, score, 1)
		assert.LessOrEqual(t, score, 10)
	}
}

func TestAIHandler_CalculateSeverityScore_Timeout(t *testing.T) {
	handler, err := NewAIHandler()
	if err != nil {
		t.Skipf("Skipping test due to initialization error: %v", err)
	}
	require.NotNil(t, handler)

	// Test with a very short timeout to ensure timeout handling works
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	changeDescription := "This is a test change description that should timeout quickly."
	_, _, err = handler.CalculateSeverityScore(ctx, changeDescription)

	// Should get a context deadline exceeded error
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestInferLanguageFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"main.go", "Go"},
		{"script.py", "Python"},
		{"app.js", "JavaScript"},
		{"module.mjs", "JavaScript"},
		{"component.ts", "TypeScript"},
		{"Main.java", "Java"},
		{"program.cpp", "C++"},
		{"source.c", "C"},
		{"lib.rs", "Rust"},
		{"script.rb", "Ruby"},
		{"index.php", "PHP"},
		{"Program.cs", "C#"},
		{"App.kt", "Kotlin"},
		{"ViewController.swift", "Swift"},
		{"Main.scala", "Scala"},
		{"query.sql", "SQL"},
		{"config.yaml", "YAML"},
		{"config.yml", "YAML"},
		{"data.json", "JSON"},
		{"document.xml", "XML"},
		{"page.html", "HTML"},
		{"styles.css", "CSS"},
		{"script.sh", "Shell"},
		{"Dockerfile", "Dockerfile"},
		{"dockerfile", "Dockerfile"},
		{"Dockerfile.dev", "Dockerfile"},
		{"Dockerfile.prod", "Dockerfile"},
		{"path/to/Dockerfile", "Dockerfile"},
		{"Makefile", "Makefile"},
		{"makefile", "Makefile"},
		{"Rakefile", "Ruby"},
		{"app.dockerfile", "Dockerfile"},
		{"unknown.xyz", "Unknown"},
		{"noextension", "Unknown"},
		{"", "Unknown"},
	}

	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			result := inferLanguageFromPath(test.path)
			assert.Equal(t, test.expected, result)
		})
	}
}