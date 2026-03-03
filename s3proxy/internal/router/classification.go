package router

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var bucketAndKeyPattern = regexp.MustCompile(`/([^/?]+)/(.+)`)

type operation int

const (
	opForward operation = iota
	opGetObject
	opPutObject
	opCreateMultipart
	opUploadPart
	opCompleteMultipart
	opAbortMultipart
)

type requestState struct {
	matchingPath bool
	bucket       string
	key          string
	op           operation
}

func operationName(op operation) string {
	switch op {
	case opGetObject:
		return "get_object"
	case opPutObject:
		return "put_object"
	case opCreateMultipart:
		return "create_multipart_upload"
	case opUploadPart:
		return "upload_part"
	case opCompleteMultipart:
		return "complete_multipart_upload"
	case opAbortMultipart:
		return "abort_multipart_upload"
	default:
		return "forward"
	}
}

func classifyRequest(req *http.Request) requestState {
	var key, bucket string
	matchingPath := match(req.URL.Path, bucketAndKeyPattern, &bucket, &key)

	if !matchingPath {
		return requestState{matchingPath: false, op: opForward}
	}

	op := opForward
	query := req.URL.Query()
	if isUploadPart(req.Method, query) {
		op = opUploadPart
	} else if isCreateMultipartUpload(req.Method, query) {
		op = opCreateMultipart
	} else if isCompleteMultipartUpload(req.Method, query) {
		op = opCompleteMultipart
	} else if isAbortMultipartUpload(req.Method, query) {
		op = opAbortMultipart
	} else if req.Method == http.MethodGet && !isUnwantedGetEndpoint(query) {
		op = opGetObject
	} else if req.Method == http.MethodPut && !isUnwantedPutEndpoint(req.Header, query) {
		op = opPutObject
	}

	return requestState{matchingPath: true, bucket: bucket, key: key, op: op}
}

func isAbortMultipartUpload(method string, query url.Values) bool {
	_, uploadID := query["uploadId"]
	return method == http.MethodDelete && uploadID
}

func isCompleteMultipartUpload(method string, query url.Values) bool {
	_, multipart := query["uploadId"]
	return method == http.MethodPost && multipart
}

func isCreateMultipartUpload(method string, query url.Values) bool {
	_, multipart := query["uploads"]
	return method == http.MethodPost && multipart
}

func isUploadPart(method string, query url.Values) bool {
	_, partNumber := query["partNumber"]
	_, uploadID := query["uploadId"]
	return method == http.MethodPut && partNumber && uploadID
}

// isUnwantedGetEndpoint returns true if request query matches non-GetObject APIs.
func isUnwantedGetEndpoint(query url.Values) bool {
	_, acl := query["acl"]
	_, attributes := query["attributes"]
	_, legalHold := query["legal-hold"]
	_, retention := query["retention"]
	_, tagging := query["tagging"]
	_, torrent := query["torrent"]
	_, uploadID := query["uploadId"]

	return acl || attributes || legalHold || retention || tagging || torrent || uploadID
}

// isUnwantedPutEndpoint returns true if request query/header matches non-PutObject APIs.
func isUnwantedPutEndpoint(header http.Header, query url.Values) bool {
	if header.Get("x-amz-copy-source") != "" {
		return true
	}

	_, partNumber := query["partNumber"]
	_, uploadID := query["uploadId"]
	_, tagging := query["tagging"]
	_, legalHold := query["legal-hold"]
	_, objectLock := query["object-lock"]
	_, retention := query["retention"]
	_, publicAccessBlock := query["publicAccessBlock"]
	_, acl := query["acl"]

	return partNumber || uploadID || tagging || legalHold || objectLock || retention || publicAccessBlock || acl
}

func isTaggingAttempt(req *http.Request) bool {
	if req.Method != http.MethodPut {
		return false
	}
	if strings.TrimSpace(req.Header.Get("x-amz-tagging")) != "" {
		return true
	}
	_, taggingQuery := req.URL.Query()["tagging"]
	return taggingQuery
}

// getMultipartHandler returns the blocking multipart handler if req targets a multipart operation.
func (r Router) getMultipartHandler(req *http.Request) http.Handler {
	switch classifyRequest(req).op {
	case opUploadPart:
		return handleUploadPart(r.log)
	case opCreateMultipart:
		return handleCreateMultipartUpload(r.log)
	case opCompleteMultipart:
		return handleCompleteMultipartUpload(r.log)
	case opAbortMultipart:
		return handleAbortMultipartUpload(r.log)
	default:
		return nil
	}
}
