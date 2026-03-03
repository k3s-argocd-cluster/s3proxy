package encryption

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
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

	wrappedBlobHeaderLen  = 1
	wrappedBlobFormatV1   = byte(1)
	wrappingKDFHKDFSHA256 = "hkdf-sha256"
	wrappingKDFVersionV1  = "v1"
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
	if len(in.CiphertextBlob) <= wrappedBlobHeaderLen+nonceSize {
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

func derivationInfo(formatVersion byte, keyID string, ctx map[string]string) string {
	return strings.Join([]string{
		"s3proxy-static-kms",
		fmt.Sprintf("format=%d", formatVersion),
		"kdf=" + wrappingKDFHKDFSHA256,
		"kdf-version=" + wrappingKDFVersionV1,
		"key-id=" + keyID,
		canonicalContext(ctx),
	}, contextDelim)
}

func wrappedBlobAAD(formatVersion byte, ctx map[string]string) []byte {
	return []byte(strings.Join([]string{
		fmt.Sprintf("format=%d", formatVersion),
		"kdf=" + wrappingKDFHKDFSHA256,
		"kdf-version=" + wrappingKDFVersionV1,
		canonicalContext(ctx),
	}, contextDelim))
}

func (s *StaticKMSClient) deriveWrappingKey(formatVersion byte, keyID string, ctx map[string]string) ([32]byte, error) {
	var wrappingKey [32]byte
	switch formatVersion {
	case wrappedBlobFormatV1:
		key, err := hkdf.Key(sha256.New, s.masterKey[:], nil, derivationInfo(formatVersion, keyID, ctx), len(wrappingKey))
		if err != nil {
			return [32]byte{}, err
		}
		copy(wrappingKey[:], key)
		return wrappingKey, nil
	default:
		return [32]byte{}, fmt.Errorf("unsupported wrapped data key format version: %d", formatVersion)
	}
}

func (s *StaticKMSClient) wrapDataKey(plaintext []byte, keyID string, ctx map[string]string) ([]byte, error) {
	formatVersion := wrappedBlobFormatV1
	wrappingKey, err := s.deriveWrappingKey(formatVersion, keyID, ctx)
	if err != nil {
		return nil, err
	}
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

	aad := wrappedBlobAAD(formatVersion, ctx)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	blob := make([]byte, wrappedBlobHeaderLen+nonceSize+len(ciphertext))
	blob[0] = formatVersion
	copy(blob[wrappedBlobHeaderLen:], nonce)
	copy(blob[wrappedBlobHeaderLen+nonceSize:], ciphertext)
	return blob, nil
}

func (s *StaticKMSClient) unwrapDataKey(ciphertextBlob []byte, keyID string, ctx map[string]string) ([]byte, error) {
	if len(ciphertextBlob) <= wrappedBlobHeaderLen+nonceSize {
		return nil, fmt.Errorf("ciphertext blob is invalid")
	}

	formatVersion := ciphertextBlob[0]
	wrappingKey, err := s.deriveWrappingKey(formatVersion, keyID, ctx)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(wrappingKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertextBlob[wrappedBlobHeaderLen : wrappedBlobHeaderLen+nonceSize]
	ciphertext := ciphertextBlob[wrappedBlobHeaderLen+nonceSize:]
	aad := wrappedBlobAAD(formatVersion, ctx)
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != dataKeyLen {
		return nil, fmt.Errorf("invalid plaintext data key length: %d", len(plaintext))
	}

	return plaintext, nil
}
