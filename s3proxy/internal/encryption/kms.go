package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
)

const (
	dataKeyLen      = 32
	nonceSize       = 12
	contextDelim    = "\x00"
	requiredCtxBuck = "bucket"
	requiredCtxKey  = "key"
)

// StaticKMSClient is a local KMS implementation that wraps generated data keys using a static master key.
type StaticKMSClient struct {
	masterKey [32]byte
}

func NewStaticKMSClient(rawKey string) *StaticKMSClient {
	return &StaticKMSClient{masterKey: deriveMasterKey(rawKey)}
}

func (s *StaticKMSClient) GenerateDataKey(_ context.Context, in *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("GenerateDataKey input cannot be nil")
	}
	if err := validateEncryptionContext(in.EncryptionContext); err != nil {
		return nil, err
	}

	plaintext := make([]byte, dataKeyLen)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("generating plaintext data key: %w", err)
	}

	keyID := defaultKeyID
	if in.KeyId != nil && strings.TrimSpace(*in.KeyId) != "" {
		keyID = strings.TrimSpace(*in.KeyId)
	}

	wrappedKey, err := s.wrapDataKey(plaintext, keyID, in.EncryptionContext)
	if err != nil {
		return nil, fmt.Errorf("wrapping data key: %w", err)
	}

	return &kms.GenerateDataKeyOutput{
		CiphertextBlob: wrappedKey,
		Plaintext:      plaintext,
		KeyId:          &keyID,
	}, nil
}

func (s *StaticKMSClient) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if in == nil {
		return nil, fmt.Errorf("Decrypt input cannot be nil")
	}
	if err := validateEncryptionContext(in.EncryptionContext); err != nil {
		return nil, err
	}
	if len(in.CiphertextBlob) <= nonceSize {
		return nil, fmt.Errorf("ciphertext blob is invalid")
	}

	keyID := defaultKeyID
	if in.KeyId != nil && strings.TrimSpace(*in.KeyId) != "" {
		keyID = strings.TrimSpace(*in.KeyId)
	}

	plaintext, err := s.unwrapDataKey(in.CiphertextBlob, keyID, in.EncryptionContext)
	if err != nil {
		return nil, fmt.Errorf("unwrapping data key: %w", err)
	}

	return &kms.DecryptOutput{
		Plaintext: plaintext,
		KeyId:     &keyID,
	}, nil
}

func deriveMasterKey(input string) [32]byte {
	input = strings.TrimSpace(input)
	if bytes, err := base64.StdEncoding.DecodeString(input); err == nil && len(bytes) == 32 {
		return [32]byte(bytes)
	}
	if bytes, err := hex.DecodeString(input); err == nil && len(bytes) == 32 {
		return [32]byte(bytes)
	}
	return sha256.Sum256([]byte(input))
}

func validateEncryptionContext(ctx map[string]string) error {
	if ctx == nil {
		return fmt.Errorf("encryption context is required")
	}
	if strings.TrimSpace(ctx[requiredCtxBuck]) == "" {
		return fmt.Errorf("encryption context requires '%s'", requiredCtxBuck)
	}
	if strings.TrimSpace(ctx[requiredCtxKey]) == "" {
		return fmt.Errorf("encryption context requires '%s'", requiredCtxKey)
	}
	return nil
}

func canonicalContext(ctx map[string]string) string {
	keys := make([]string, 0, len(ctx))
	for k := range ctx {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+ctx[k])
	}
	return strings.Join(pairs, contextDelim)
}

func (s *StaticKMSClient) deriveWrappingKey(keyID string, ctx map[string]string) [32]byte {
	mac := hmac.New(sha256.New, s.masterKey[:])
	_, _ = mac.Write([]byte(keyID))
	_, _ = mac.Write([]byte(contextDelim))
	_, _ = mac.Write([]byte(canonicalContext(ctx)))
	sum := mac.Sum(nil)
	return [32]byte(sum)
}

func (s *StaticKMSClient) wrapDataKey(plaintext []byte, keyID string, ctx map[string]string) ([]byte, error) {
	wrappingKey := s.deriveWrappingKey(keyID, ctx)
	block, err := aes.NewCipher(wrappingKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	aad := []byte(canonicalContext(ctx))
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return append(nonce, ciphertext...), nil
}

func (s *StaticKMSClient) unwrapDataKey(ciphertextBlob []byte, keyID string, ctx map[string]string) ([]byte, error) {
	wrappingKey := s.deriveWrappingKey(keyID, ctx)
	block, err := aes.NewCipher(wrappingKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertextBlob[:nonceSize]
	ciphertext := ciphertextBlob[nonceSize:]
	aad := []byte(canonicalContext(ctx))
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != dataKeyLen {
		return nil, fmt.Errorf("invalid plaintext data key length: %d", len(plaintext))
	}

	return plaintext, nil
}
