package handshake

import (
	"crypto"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/golang/mock/gomock"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestHandshake(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Handshake Suite")
}

var mockCtrl *gomock.Controller

var _ = BeforeEach(func() {
	mockCtrl = gomock.NewController(GinkgoT())
})

var _ = AfterEach(func() {
	mockCtrl.Finish()
})

var cipherSuites = []*qtlsCipherSuiteTLS13{
	{
		ID:     tls.TLS_AES_128_GCM_SHA256,
		KeyLen: 16,
		AEAD:   qtlsAEADAESGCMTLS13,
		Hash:   crypto.SHA256,
	},
	{
		ID:     tls.TLS_AES_256_GCM_SHA384,
		KeyLen: 32,
		AEAD:   qtlsAEADAESGCMTLS13,
		Hash:   crypto.SHA384,
	},
	{
		ID:     tls.TLS_CHACHA20_POLY1305_SHA256,
		KeyLen: 32,
		AEAD:   nil, // will be set by init
		Hash:   crypto.SHA256,
	},
}

func splitHexString(s string) (slice []byte) {
	for _, ss := range strings.Split(s, " ") {
		if ss[0:2] == "0x" {
			ss = ss[2:]
		}
		d, err := hex.DecodeString(ss)
		ExpectWithOffset(1, err).ToNot(HaveOccurred())
		slice = append(slice, d...)
	}
	return
}

func init() {
	val := cipherSuiteTLS13ByID(tls.TLS_CHACHA20_POLY1305_SHA256)
	chacha := (*mockCipherSuiteTLS13)(unsafe.Pointer(val))
	for _, s := range cipherSuites {
		if s.ID == tls.TLS_CHACHA20_POLY1305_SHA256 {
			if s.KeyLen != chacha.KeyLen || s.Hash != chacha.Hash {
				fmt.Printf("%#v\n", chacha)
				panic("invalid parameters for ChaCha20")
			}
			s.AEAD = chacha.AEAD
		}
	}
}
