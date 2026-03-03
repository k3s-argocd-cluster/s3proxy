package router

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	logger "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestWriteS3Error_ZeroStatusCodeFallsBackTo500(t *testing.T) {
	w := httptest.NewRecorder()
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 0}},
			Err:      errors.New("backend failure"),
		},
	}

	require.NotPanics(t, func() {
		writeS3Error(w, err, logger.New())
	})
	require.Equal(t, http.StatusBadGateway, w.Code)
}

func TestWriteS3Error_ContextCanceledReturnsRequestTimeout(t *testing.T) {
	w := httptest.NewRecorder()
	err := &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: 0}},
			Err:      context.Canceled,
		},
	}

	require.NotPanics(t, func() {
		writeS3Error(w, err, logger.New())
	})
	require.Equal(t, http.StatusRequestTimeout, w.Code)
}
