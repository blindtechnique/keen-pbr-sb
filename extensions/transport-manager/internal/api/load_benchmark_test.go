package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Real decoder functions; in-memory requests only, no server/admin operations.
func BenchmarkLoadInputBoundaries(b *testing.B) {
	singlePrefix, singleSuffix := `{"link":"`, `"}`
	batchPrefix, batchSuffix := `{"transports":[{"link":"`, `"}]}`
	pad := func(prefix, suffix string, limit int) string {
		return prefix + strings.Repeat("x", limit-len(prefix)-len(suffix)) + suffix
	}
	single := pad(singlePrefix, singleSuffix, 64<<10)
	batch := pad(batchPrefix, batchSuffix, 4<<20)
	for _, test := range []struct {
		name, body string
		batch      bool
		wantError  bool
	}{
		{"single_64KiB", single, false, false},
		{"single_64KiB_plus_1", single + " ", false, true},
		{"batch_4MiB", batch, true, false},
		{"batch_4MiB_plus_1", batch + " ", true, true},
		{"batch_512_nodes", `{"transports":[` + string(bytes.TrimSuffix(bytes.Repeat([]byte(`{"link":"vless://00000000-0000-4000-8000-000000000001@proxy.example:443"},`), 512), []byte(","))) + `]}`, true, false},
		{"batch_513_nodes", `{"transports":[` + strings.TrimSuffix(strings.Repeat(`{},`, 513), ",") + `]}`, true, true},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.body)))
			for i := 0; i < b.N; i++ {
				reader := &fuzzCountingReader{reader: strings.NewReader(test.body)}
				request := &http.Request{Body: io.NopCloser(reader)}
				recorder := httptest.NewRecorder()
				var err error
				limit := 64 << 10
				if test.batch {
					limit = 4 << 20
					_, err = decodeTransportBatch(recorder, request)
				} else {
					_, err = decodeTransportSpec(recorder, request)
				}
				if (err != nil) != test.wantError || reader.read > limit+1 {
					b.Fatalf("boundary changed: err=%v read=%d limit=%d", err, reader.read, limit)
				}
			}
		})
	}
}
