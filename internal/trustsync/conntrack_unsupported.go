//go:build !linux

package trustsync

func newConntrackInspector() ConntrackInspector {
	return nil
}
