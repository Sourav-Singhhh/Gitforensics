package detect

import (
	"testing"
)

func TestEvaluateContext(t *testing.T) {
	// Keyword within 100-byte window
	payload := []byte("const aws_secret_access_key = 'AKIAIOSFODNN7EXAMPLE';\n")
	start := 32
	end := 52

	score, keywords := EvaluateContext(payload, start, end)
	if score != 20 {
		t.Errorf("expected context score +20, got %d", score)
	}
	if len(keywords) == 0 {
		t.Errorf("expected detected keywords, got %v", keywords)
	}

	// Multiple keywords do NOT stack (+20 maximum)
	multiPayload := []byte("api_key = token = secret = password = authorization = 'AKIAIOSFODNN7EXAMPLE';\n")
	startMulti := 55
	endMulti := 75
	multiScore, multiKeywords := EvaluateContext(multiPayload, startMulti, endMulti)
	if multiScore != 20 {
		t.Errorf("expected multiple keywords to not stack (score must be 20), got %d", multiScore)
	}
	if len(multiKeywords) < 2 {
		t.Errorf("expected multiple keywords recorded, got %v", multiKeywords)
	}

	// No keywords
	noKwPayload := []byte("just some innocent plain text without any matching words: AKIAIOSFODNN7EXAMPLE\n")
	startNoKw := 59
	endNoKw := 79
	noKwScore, noKwList := EvaluateContext(noKwPayload, startNoKw, endNoKw)
	if noKwScore != 0 {
		t.Errorf("expected 0 score for no keywords, got %d", noKwScore)
	}
	if len(noKwList) != 0 {
		t.Errorf("expected empty keywords list, got %v", noKwList)
	}
}

func TestEvaluatePath(t *testing.T) {
	// Sensitive filename (.env)
	score, isSensitive, isTest := EvaluatePath("config/.env")
	if score != 10 || !isSensitive || isTest {
		t.Errorf("expected +10 sensitive bonus on .env, got score=%d, sens=%v, test=%v", score, isSensitive, isTest)
	}

	// Sensitive key file (id_rsa)
	score, isSensitive, isTest = EvaluatePath("keys/id_rsa")
	if score != 10 || !isSensitive {
		t.Errorf("expected +10 sensitive bonus on id_rsa, got score=%d", score)
	}

	// Test directory penalty (-30)
	score, isSensitive, isTest = EvaluatePath("tests/fixtures/sample.txt")
	if score != -30 || !isTest {
		t.Errorf("expected -30 penalty on test path, got score=%d, test=%v", score, isTest)
	}

	// Sensitive file inside test directory: +10 - 30 = -20
	score, isSensitive, isTest = EvaluatePath("test/fixtures/.env")
	if score != -20 || !isSensitive || !isTest {
		t.Errorf("expected -20 combined score on test/.env, got score=%d", score)
	}

	// Non-test word with substring "test" (e.g. "contest" or "attestation") must NOT trigger penalty
	score, isSensitive, isTest = EvaluatePath("contest/attestation/document.txt")
	if score != 0 || isTest {
		t.Errorf("expected 0 penalty for contest/attestation, got score=%d, isTest=%v", score, isTest)
	}
}
