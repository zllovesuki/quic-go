//go:build !linux

package quic

func errShouldDisableUDPGSO(err error) bool {
	return false
}
