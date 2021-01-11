package wire

import (
	"bytes"
	"fmt"
	"io"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ACK_FREQUENCY frame", func() {
	Context("when parsing", func() {
		It("parses", func() {
			data := []byte{0xaf}
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			data = append(data, encodeVarInt(0xcafe)...)     // packet tolerance
			data = append(data, encodeVarInt(1337)...)       // update max ack delay
			data = append(data, 1)                           // ignore order
			b := bytes.NewReader(data)
			frame, err := parseAckFrequencyFrame(b, versionIETFFrames)
			Expect(err).ToNot(HaveOccurred())
			Expect(frame.SequenceNumber).To(Equal(uint64(0xdeadbeef)))
			Expect(frame.PacketTolerance).To(Equal(uint64(0xcafe)))
			Expect(frame.UpdateMaxAckDelay).To(Equal(1337 * time.Microsecond))
			Expect(frame.IgnoreOrder).To(BeTrue())
		})

		It("errors when the Packet Tolerance field is 0", func() {
			data := []byte{0xaf}
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			data = append(data, encodeVarInt(0)...)          // packet tolerance
			data = append(data, encodeVarInt(1337)...)       // update max ack delay
			data = append(data, 2)                           // ignore order
			b := bytes.NewReader(data)
			_, err := parseAckFrequencyFrame(b, versionIETFFrames)
			Expect(err).To(MatchError("invalid Packet Tolerance: 0"))
		})

		It("errors when the Ignore Order field contains a value other than 0 or 1", func() {
			data := []byte{0xaf}
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			data = append(data, encodeVarInt(0xcafe)...)     // packet tolerance
			data = append(data, encodeVarInt(1337)...)       // update max ack delay
			data = append(data, 2)                           // ignore order
			b := bytes.NewReader(data)
			_, err := parseAckFrequencyFrame(b, versionIETFFrames)
			Expect(err).To(MatchError("invalid Ignore Order"))
		})

		It("errors on EOFs", func() {
			data := []byte{0xaf}
			data = append(data, encodeVarInt(0xdeadbeef)...) // sequence number
			data = append(data, encodeVarInt(0xcafe)...)     // packet tolerance
			data = append(data, encodeVarInt(1337)...)       // update max ack delay
			data = append(data, 1)                           // ignore order
			_, err := parseAckFrequencyFrame(bytes.NewReader(data), versionIETFFrames)
			Expect(err).NotTo(HaveOccurred())
			for i := range data {
				_, err := parseAckFrequencyFrame(bytes.NewReader(data[0:i]), versionIETFFrames)
				Expect(err).To(MatchError(io.EOF))
			}
		})
	})

	Context("when writing", func() {
		for _, ignore := range []bool{false, true} {
			ignoreOrder := ignore

			It(fmt.Sprintf("writes a frame with Ignore Order = %t", ignoreOrder), func() {
				frame := &AckFrequencyFrame{
					SequenceNumber:    0xdecafbad,
					PacketTolerance:   0xdeadbeef,
					UpdateMaxAckDelay: 12345 * time.Microsecond,
					IgnoreOrder:       ignoreOrder,
				}
				buf := &bytes.Buffer{}
				Expect(frame.Write(buf, versionIETFFrames)).To(Succeed())
				expected := []byte{0xaf}
				expected = append(expected, encodeVarInt(0xdecafbad)...)
				expected = append(expected, encodeVarInt(0xdeadbeef)...)
				expected = append(expected, encodeVarInt(12345)...)
				if ignoreOrder {
					expected = append(expected, 1)
				} else {
					expected = append(expected, 0)
				}
				Expect(buf.Bytes()).To(Equal(expected))
				Expect(frame.Length(versionIETFFrames)).To(BeEquivalentTo(buf.Len()))
				f, err := parseAckFrequencyFrame(bytes.NewReader(buf.Bytes()), versionIETFFrames)
				Expect(err).ToNot(HaveOccurred())
				Expect(f).To(Equal(frame))
			})
		}
	})
})
