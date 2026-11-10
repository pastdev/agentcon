package gql

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarize(t *testing.T) {
	type testCase struct {
		query      string
		wantLen    int
		wantType0  string
		wantField0 string
		wantType1  string
		wantField1 string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		ops, err := Summarize(tc.query)
		require.NoError(t, err)
		require.Len(t, ops, tc.wantLen)
		assert.Equal(t, tc.wantType0, ops[0].Type)
		require.Len(t, ops[0].Fields, 2)
		assert.Equal(t, tc.wantField0, ops[0].Fields[0])
		assert.Equal(t, tc.wantType1, ops[1].Type)
		assert.Equal(t, tc.wantField1, ops[1].Fields[0])
	}

	t.Run("expands fragments into mutation fields", func(t *testing.T) {
		tester(t, testCase{
			query: `
mutation Sneaky { ...F  ... on Mutation { addComment(input:{}) { clientMutationId } } }
fragment F on Mutation { deleteRepository(input: {repositoryId: "x"}) { clientMutationId } }
query Q { viewer { login } }`,
			wantLen:    2,
			wantType0:  "mutation",
			wantField0: "deleteRepository",
			wantType1:  "query",
			wantField1: "viewer",
		})
	})
}

func TestFromHTTP(t *testing.T) {
	type testCase struct {
		method         string
		query          url.Values
		header         http.Header
		body           []byte
		wantLen        int
		wantFirstField string
		wantLastField  string
		wantLastType   string
		wantType0      string
		wantErr        bool
		nestedOK       bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		ops, err := FromHTTP(tc.method, tc.query, tc.header, tc.body)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		if tc.nestedOK {
			return
		}
		require.Len(t, ops, tc.wantLen)
		first, last := ops[0], ops[len(ops)-1]
		if tc.wantFirstField != "" {
			assert.Equal(t, tc.wantFirstField, first.Fields[0])
		}
		if tc.wantLastField != "" {
			assert.Equal(t, tc.wantLastField, last.Fields[0])
		}
		if tc.wantLastType != "" {
			assert.Equal(t, tc.wantLastType, last.Type)
		}
		if tc.wantType0 != "" {
			assert.Equal(t, tc.wantType0, first.Type)
		}
	}

	jsonH := http.Header{"Content-Type": {"application/json"}}
	t.Run("parses a json batch", func(t *testing.T) {
		tester(t, testCase{
			method:        "POST",
			header:        jsonH,
			body:          []byte(`[{"query":"{ viewer { login } }"},{"query":"mutation { mergePullRequest(input:{}) { clientMutationId } }"}]`),
			wantLen:       2,
			wantLastField: "mergePullRequest",
		})
	})
	t.Run("rejects a persisted query", func(t *testing.T) {
		tester(t, testCase{
			method:  "POST",
			header:  jsonH,
			body:    []byte(`{"extensions":{"persistedQuery":{}}}`),
			wantErr: true,
		})
	})
	t.Run("rejects duplicate query keys in an object", func(t *testing.T) {
		tester(t, testCase{
			method:  "POST",
			header:  jsonH,
			body:    []byte(`{"query":"{ viewer { login } }","query":"mutation { deleteRepository(input:{}) { clientMutationId } }"}`),
			wantErr: true,
		})
	})
	t.Run("rejects duplicate query keys in a batch item", func(t *testing.T) {
		tester(t, testCase{
			method:  "POST",
			header:  jsonH,
			body:    []byte(`[{"query":"{ a }"},{"query":"{ b }","query":"{ c }"}]`),
			wantErr: true,
		})
	})
	t.Run("allows nested keys named query", func(t *testing.T) {
		tester(t, testCase{
			method:   "POST",
			header:   jsonH,
			body:     []byte(`{"query":"{ a }","variables":{"query":"x","query2":"y"}}`),
			nestedOK: true,
		})
	})
	t.Run("rejects a case-variant duplicate key", func(t *testing.T) {
		tester(t, testCase{
			method:  "POST",
			header:  jsonH,
			body:    []byte(`{"query":"mutation{destroy}","QUERY":"query{a}"}`),
			wantErr: true,
		})
	})
	t.Run("expands a _json wrapper", func(t *testing.T) {
		tester(t, testCase{
			method:        "POST",
			header:        jsonH,
			body:          []byte(`{"_json":[{"query":"query{a}"},{"query":"mutation{destroy}"}]}`),
			wantLen:       2,
			wantLastField: "destroy",
			wantLastType:  "mutation",
		})
	})
	t.Run("includes the url query together with the body", func(t *testing.T) {
		tester(t, testCase{
			method:         "POST",
			query:          url.Values{"query": {"mutation{destroy}"}},
			header:         jsonH,
			body:           []byte(`{"query":"query{a}"}`),
			wantLen:        2,
			wantFirstField: "destroy",
		})
	})
	t.Run("parses a url-only mutation", func(t *testing.T) {
		tester(t, testCase{
			method:    "POST",
			query:     url.Values{"query": {"mutation{destroy}"}},
			header:    http.Header{},
			wantLen:   1,
			wantType0: "mutation",
		})
	})
	t.Run("rejects a repeated url query", func(t *testing.T) {
		tester(t, testCase{
			method:  "GET",
			query:   url.Values{"query": {"query{a}", "mutation{destroy}"}},
			header:  http.Header{},
			wantErr: true,
		})
	})
}
