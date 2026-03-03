package router

import (
	"encoding/xml"
	"fmt"
)

// ContentSHA256MismatchError is a helper struct to create an XML formatted error message.
// S3 clients parse this shape, so it must remain compatible.
type ContentSHA256MismatchError struct {
	XMLName                     xml.Name `xml:"Error"`
	Code                        string   `xml:"Code"`
	Message                     string   `xml:"Message"`
	ClientComputedContentSHA256 string   `xml:"ClientComputedContentSHA256"`
	S3ComputedContentSHA256     string   `xml:"S3ComputedContentSHA256"`
}

// NewContentSHA256MismatchError creates a new ContentSHA256MismatchError.
func NewContentSHA256MismatchError(clientComputedContentSHA256, s3ComputedContentSHA256 string) ContentSHA256MismatchError {
	return ContentSHA256MismatchError{
		Code:                        "XAmzContentSHA256Mismatch",
		Message:                     "The provided 'x-amz-content-sha256' header does not match what was computed.",
		ClientComputedContentSHA256: clientComputedContentSHA256,
		S3ComputedContentSHA256:     s3ComputedContentSHA256,
	}
}

// byteSliceToByteArray casts a byte slice to a byte array of length 32.
func byteSliceToByteArray(input []byte) ([32]byte, error) {
	if len(input) != 32 {
		return [32]byte{}, fmt.Errorf("input length mismatch, got: %d", len(input))
	}
	return ([32]byte)(input), nil
}
