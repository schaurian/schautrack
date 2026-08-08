package openapi

import (
	"strings"
	"testing"
)

// TestEveryBodyOperationDeclares413 pins #349. decodeV1 caps every v1 request
// body and answers 413, so the response belongs to "this operation takes a
// body" rather than to any individual endpoint. Before this was derived, only
// the AI image upload declared it and a generated client had no 413 branch for
// the other thirteen.
func TestEveryBodyOperationDeclares413(t *testing.T) {
	doc := Build("", "")
	for path, item := range doc.Paths {
		for method, op := range item.Operations() {
			if op.RequestBody == nil {
				continue
			}
			if op.Responses["413"] == nil {
				t.Errorf("%s %s takes a request body but declares no 413", method, path)
			}
		}
	}
}

// TestNoBodylessOperationDeclares413 is the other half: a 413 on an operation
// that takes no body would be a lie, and would train clients to handle a status
// the server cannot produce there.
func TestNoBodylessOperationDeclares413(t *testing.T) {
	doc := Build("", "")
	for path, item := range doc.Paths {
		for method, op := range item.Operations() {
			if op.RequestBody == nil && op.Responses["413"] != nil {
				t.Errorf("%s %s declares 413 but accepts no request body", method, path)
			}
		}
	}
}

// TestAIEstimateKeepsItsOwn413 checks the derived pass does not overwrite an
// operation that documents a different limit. The image upload is 10 MB, not
// the 1 MB decodeV1 cap.
func TestAIEstimateKeepsItsOwn413(t *testing.T) {
	doc := Build("", "")
	op := doc.Paths["/ai/estimate"].Post
	resp := op.Responses["413"]
	if resp == nil {
		t.Fatal("POST /ai/estimate lost its 413")
	}
	if want := "10 MB"; !strings.Contains(resp.Description, want) {
		t.Errorf("POST /ai/estimate's 413 = %q, want it to still mention %q", resp.Description, want)
	}
}

// TestIdempotentOperationsDeclareTheReplayHeader pins #360. A replay repeats
// the original status code, so the header is the only way a client can tell one
// from a fresh create — prose in the parameter description does not reach a
// generated client.
func TestIdempotentOperationsDeclareTheReplayHeader(t *testing.T) {
	doc := Build("", "")
	found := 0
	for path, item := range doc.Paths {
		for method, op := range item.Operations() {
			if !acceptsIdempotencyKey(op) {
				continue
			}
			found++
			for code, resp := range op.Responses {
				if code < "200" || code > "299" {
					continue
				}
				if _, ok := resp.Headers["Idempotency-Replayed"]; !ok {
					t.Errorf("%s %s accepts Idempotency-Key but its %s does not declare Idempotency-Replayed",
						method, path, code)
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no operation accepts Idempotency-Key — the derivation is keyed off nothing")
	}
}

// TestNonIdempotentOperationsOmitTheReplayHeader is the inverse: an endpoint
// that ignores the key must not advertise a header it will never send.
func TestNonIdempotentOperationsOmitTheReplayHeader(t *testing.T) {
	doc := Build("", "")
	for path, item := range doc.Paths {
		for method, op := range item.Operations() {
			if acceptsIdempotencyKey(op) {
				continue
			}
			for code, resp := range op.Responses {
				if _, ok := resp.Headers["Idempotency-Replayed"]; ok {
					t.Errorf("%s %s does not accept Idempotency-Key but its %s declares Idempotency-Replayed",
						method, path, code)
				}
			}
		}
	}
}
