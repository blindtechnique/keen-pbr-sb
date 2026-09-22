package transport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Pure generation only: no process start, interface, route or config-file write.
// ns/op is NOT application/recovery time, B/op is NOT sing-box resident memory.
func BenchmarkLoadConfigBuild(b *testing.B) {
	for _, count := range []int{1, 5, 10} {
		specs := make([]TransportSpec, count)
		for i := range specs {
			specs[i] = TransportSpec{
				Tag: fmt.Sprintf("load_%d", i), Type: "sing-box",
				Interface:    fmt.Sprintf("load%d", i),
				OutboundJSON: `{"type":"vless","server":"proxy.example","server_port":443,"uuid":"00000000-0000-4000-8000-000000000001","tls":{"enabled":true,"server_name":"proxy.example"}}`,
			}
		}
		for _, mode := range []string{"isolated", "shared"} {
			b.Run(fmt.Sprintf("%s/%d", mode, count), func(b *testing.B) {
				b.ReportAllocs()
				for n := 0; n < b.N; n++ {
					if mode == "shared" {
						config, err := BuildSharedSingBoxConfig(specs)
						if err != nil {
							b.Fatal(err)
						}
						if _, err = json.Marshal(config); err != nil {
							b.Fatal(err)
						}
					} else {
						for _, spec := range specs {
							config, err := (&SingBox{spec: spec}).buildConfig()
							if err != nil {
								b.Fatal(err)
							}
							if _, err = json.Marshal(config); err != nil {
								b.Fatal(err)
							}
						}
					}
				}
			})
		}
	}
}

// Exercise only an owned temporary file, never the installed runtime log.
func TestLoadRuntimeLogBoundaryWithOpenWriter(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Keenetic/POSIX append-and-truncate semantics; Windows denies truncate on an append-only handle")
	}
	path := filepath.Join(t.TempDir(), "synthetic.log")
	writer, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	const limit = 2 * 1024 * 1024
	for _, size := range []int64{limit - 1, limit, limit + 1, 4 * limit} {
		if err := writer.Truncate(size); err != nil {
			t.Fatal(err)
		}
		truncateRuntimeLogFile(path)
		info, err := writer.Stat()
		if err != nil {
			t.Fatal(err)
		}
		want := size
		if size > limit {
			want = 0
		}
		if info.Size() != want {
			t.Fatalf("size=%d after reconciliation=%d want=%d", size, info.Size(), want)
		}
		if _, err := writer.WriteString("next\n"); err != nil {
			t.Fatal(err)
		}
		info, err = os.Stat(path)
		if err != nil || info.Size() != want+5 {
			t.Fatalf("open append writer lost after truncate: info=%v err=%v", info, err)
		}
	}
}
