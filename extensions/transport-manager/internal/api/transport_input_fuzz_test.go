package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/infaprim/mykeenpbr/internal/transport"
)

// These pin the existing production boundaries, not new import restrictions.
const fuzzSingleBodyLimit = 64 << 10
const fuzzBatchBodyLimit = 4 << 20

type fuzzCountingReader struct {
	reader io.Reader
	read   int
}

func (r *fuzzCountingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.read += n
	return n, err
}

func decodeFuzzTransportInput(t *testing.T, body string, batch bool) ([]transport.TransportSpec, error) {
	t.Helper()
	reader := &fuzzCountingReader{reader: strings.NewReader(body)}
	request := &http.Request{Body: io.NopCloser(reader)}
	recorder := httptest.NewRecorder()
	limit := fuzzSingleBodyLimit
	var specs []transport.TransportSpec
	var err error
	if batch {
		limit = fuzzBatchBodyLimit
		specs, err = decodeTransportBatch(recorder, request)
	} else {
		var spec transport.TransportSpec
		spec, err = decodeTransportSpec(recorder, request)
		if err == nil {
			specs = []transport.TransportSpec{spec}
		}
	}
	if reader.read > limit+1 {
		t.Fatalf("decoder read beyond body limit: bytes=%d limit=%d", reader.read, limit)
	}
	return specs, err
}

func FuzzTransportInput(f *testing.F) {
	for _, body := range []string{
		`null`, `{}`, `[]`, `{} {}`, `{"unknown":true}`, `{"display_name":"\u202eexample"}`,
		`{"tag":"example","type":"sing-box","interface":"fuzz0","link":"vless://example-id@proxy.example:443"}`,
		`{"transports":[]}`, `{"transports":[null]}`,
		`{"transports":[{"tag":"example","type":"sing-box","interface":"fuzz0","link":"ss://YWVzLTEyOC1nY206ZXhhbXBsZQ@proxy.example:8388"}]}`,
	} {
		f.Add(body, false)
		f.Add(body, true)
	}
	f.Fuzz(func(t *testing.T, body string, batch bool) {
		if len(body) > fuzzBatchBodyLimit+1 {
			return
		}
		specs, err := decodeFuzzTransportInput(t, body, batch)
		if err != nil {
			return
		}
		if !json.Valid([]byte(body)) {
			t.Fatal("decoder accepted invalid or multiple JSON values")
		}
		if batch && (len(specs) < 1 || len(specs) > maximumTransportBatchSize) {
			t.Fatal("decoder accepted an out-of-bounds batch")
		}
		for _, spec := range specs {
			if err := transport.ValidateDisplayName(spec.DisplayName); err != nil {
				t.Fatal("decoder accepted an invalid display name")
			}
		}
		var canonical []byte
		if batch {
			canonical, err = json.Marshal(map[string]any{"transports": specs})
		} else {
			canonical, err = json.Marshal(specs[0])
		}
		if err != nil {
			t.Fatal("decoded spec is not JSON-serializable")
		}
		// Default struct fields and replacement of invalid UTF-8 may expand
		// small inputs; decoded strings must still have a linear bound.
		if len(canonical) > 6*len(body)+256*len(specs)+1024 {
			t.Fatal("decoded spec expansion exceeded bound")
		}
		limit := fuzzSingleBodyLimit
		if batch {
			limit = fuzzBatchBodyLimit
		}
		if len(canonical) <= limit {
			reloaded, err := decodeFuzzTransportInput(t, string(canonical), batch)
			if err != nil || !reflect.DeepEqual(specs, reloaded) {
				t.Fatal("transport input changed after JSON round-trip")
			}
		}
	})
}

func TestTransportInputResourceBoundaries(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprintf("batch=%t", batch), func(t *testing.T) {
			prefix, suffix := `{"link":"`, `"}`
			limit := fuzzSingleBodyLimit
			if batch {
				prefix, suffix = `{"transports":[`+prefix, suffix+`]}`
				limit = fuzzBatchBodyLimit
			}
			body := prefix + strings.Repeat("x", limit-len(prefix)-len(suffix)) + suffix
			if _, err := decodeFuzzTransportInput(t, body, batch); err != nil {
				t.Fatal("existing body limit rejected at its boundary")
			}
			for _, oversized := range []string{body + " ", prefix + "x" + body[len(prefix):]} {
				if _, err := decodeFuzzTransportInput(t, oversized, batch); err == nil {
					t.Fatal("body above existing limit was accepted")
				}
			}
		})
	}
	for _, count := range []int{0, 1, 512, 513} {
		items := bytes.Repeat([]byte(`{},`), count)
		items = bytes.TrimSuffix(items, []byte(","))
		_, err := decodeFuzzTransportInput(t, `{"transports":[`+string(items)+`]}`, true)
		if (err == nil) != (count > 0 && count <= 512) {
			t.Fatalf("batch node boundary changed: count=%d", count)
		}
	}
}
