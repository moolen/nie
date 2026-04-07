package test

import (
	"reflect"
	"testing"
)

func TestNieRunArgsUsesRunSubcommandAndConfigFlag(t *testing.T) {
	got := nieRunArgs("/tmp/nie.yaml")
	want := []string{"run", "--config", "/tmp/nie.yaml"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("nieRunArgs() = %v, want %v", got, want)
	}
}
