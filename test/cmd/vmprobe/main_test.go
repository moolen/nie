package main

import "testing"

func TestFormatProbeResult(t *testing.T) {
	line := formatProbeResult(probeResult{
		Kind:   "tcp",
		Phase:  "direct",
		Target: "192.168.56.1:18080",
		Result: "success",
	})

	want := "kind=tcp phase=direct target=192.168.56.1:18080 result=success"
	if line != want {
		t.Fatalf("line = %q, want %q", line, want)
	}
}
