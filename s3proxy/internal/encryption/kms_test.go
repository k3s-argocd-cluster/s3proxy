package encryption

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/require"
)

func TestDeriveMasterKey(t *testing.T) {
	t.Parallel()

	raw := [32]byte{}
	for i := range raw {
		raw[i] = byte(i + 1)
	}

	t.Run("base64 input", func(t *testing.T) {
		t.Parallel()
		encoded := base64.StdEncoding.EncodeToString(raw[:])
		got := deriveMasterKey(encoded)
		require.Equal(t, raw, got)
	})

	t.Run("hex input", func(t *testing.T) {
		t.Parallel()
		encoded := hex.EncodeToString(raw[:])
		got := deriveMasterKey(encoded)
		require.Equal(t, raw, got)
	})

	t.Run("fallback sha256 input", func(t *testing.T) {
		t.Parallel()
		input := "not-a-raw-32-byte-key"
		got := deriveMasterKey(input)
		require.Equal(t, sha256.Sum256([]byte(input)), got)
	})
}

func TestValidateEncryptionContext(t *testing.T) {
	t.Parallel()

	valid := map[string]string{
		"bucket": "b",
		"key":    "k",
	}

	require.NoError(t, validateEncryptionContext(valid))
	require.ErrorContains(t, validateEncryptionContext(nil), "encryption context is required")
	require.ErrorContains(t, validateEncryptionContext(map[string]string{"key": "k"}), "requires 'bucket'")
	require.ErrorContains(t, validateEncryptionContext(map[string]string{"bucket": "b"}), "requires 'key'")
}

func TestWrapUnwrapDataKey_BindsFormatContextAndKeyID(t *testing.T) {
	t.Parallel()

	client := NewStaticKMSClient("test-static-key")
	keyID := "test-key-id"
	ctx := map[string]string{
		"bucket": "test-bucket",
		"key":    "nested/object.txt",
	}

	plaintext := make([]byte, dataKeyLen)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ciphertextBlob, err := client.wrapDataKey(plaintext, keyID, ctx)
	require.NoError(t, err)
	require.Greater(t, len(ciphertextBlob), wrappedBlobHeaderLen+nonceSize)
	require.Equal(t, wrappedBlobFormatV1, ciphertextBlob[0])

	decrypted, err := client.unwrapDataKey(ciphertextBlob, keyID, ctx)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	_, err = client.unwrapDataKey(ciphertextBlob, "wrong-key-id", ctx)
	require.Error(t, err)

	_, err = client.unwrapDataKey(ciphertextBlob, keyID, map[string]string{
		"bucket": "other-bucket",
		"key":    ctx["key"],
	})
	require.Error(t, err)

	tamperedFormat := append([]byte(nil), ciphertextBlob...)
	tamperedFormat[0] = 2
	_, err = client.unwrapDataKey(tamperedFormat, keyID, ctx)
	require.ErrorContains(t, err, "unsupported wrapped data key format version")

	tamperedCiphertext := append([]byte(nil), ciphertextBlob...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0xFF
	_, err = client.unwrapDataKey(tamperedCiphertext, keyID, ctx)
	require.Error(t, err)

	_, err = client.unwrapDataKey(ciphertextBlob[:wrappedBlobHeaderLen+nonceSize], keyID, ctx)
	require.ErrorContains(t, err, "ciphertext blob is invalid")
}

func TestGenerateDataKeyAndDecrypt(t *testing.T) {
	t.Parallel()

	client := NewStaticKMSClient("integration-like-static-key")
	ctx := map[string]string{
		"bucket": "bucket-a",
		"key":    "object-a",
	}

	out, err := client.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
		KeyId:             nil,
		EncryptionContext: ctx,
	})
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, defaultKeyID, *out.KeyId)
	require.Len(t, out.Plaintext, dataKeyLen)
	require.Greater(t, len(out.CiphertextBlob), wrappedBlobHeaderLen+nonceSize)

	dec, err := client.Decrypt(context.Background(), &kms.DecryptInput{
		KeyId:             out.KeyId,
		CiphertextBlob:    out.CiphertextBlob,
		EncryptionContext: ctx,
	})
	require.NoError(t, err)
	require.Equal(t, out.Plaintext, dec.Plaintext)

	customKeyID := "custom-key-id"
	customOut, err := client.GenerateDataKey(context.Background(), &kms.GenerateDataKeyInput{
		KeyId:             &customKeyID,
		EncryptionContext: ctx,
	})
	require.NoError(t, err)

	_, err = client.Decrypt(context.Background(), &kms.DecryptInput{
		CiphertextBlob:    customOut.CiphertextBlob,
		EncryptionContext: ctx,
	})
	require.Error(t, err)

	_, err = client.GenerateDataKey(context.Background(), nil)
	require.ErrorContains(t, err, "GenerateDataKey input cannot be nil")

	_, err = client.Decrypt(context.Background(), nil)
	require.ErrorContains(t, err, "Decrypt input cannot be nil")
}
