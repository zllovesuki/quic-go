package wire

import (
	"bytes"
	"errors"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/quicvarint"
)

type AckFrequencyFrame struct {
	SequenceNumber    uint64
	PacketTolerance   uint64
	UpdateMaxAckDelay time.Duration
	IgnoreOrder       bool
}

func parseAckFrequencyFrame(r *bytes.Reader, _ protocol.VersionNumber) (*AckFrequencyFrame, error) {
	if _, err := r.ReadByte(); err != nil {
		return nil, err
	}

	seq, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	tol, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	if tol == 0 {
		return nil, errors.New("invalid Packet Tolerance: 0")
	}
	// TODO: fix possible overflow here by imposing a limit (see https://github.com/janaiyengar/ack-frequency/issues/43).
	mad, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	ignoreOrder, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if ignoreOrder != 0 && ignoreOrder != 1 {
		return nil, errors.New("invalid Ignore Order")
	}
	return &AckFrequencyFrame{
		SequenceNumber:    seq,
		PacketTolerance:   tol,
		UpdateMaxAckDelay: time.Duration(mad) * time.Microsecond,
		IgnoreOrder:       ignoreOrder == 1,
	}, nil
}

func (f *AckFrequencyFrame) Write(b *bytes.Buffer, _ protocol.VersionNumber) error {
	b.WriteByte(0xaf)
	quicvarint.Write(b, f.SequenceNumber)
	quicvarint.Write(b, f.PacketTolerance)
	quicvarint.Write(b, uint64(f.UpdateMaxAckDelay/time.Microsecond))
	if f.IgnoreOrder {
		b.WriteByte(1)
	} else {
		b.WriteByte(0)
	}
	return nil
}

func (f *AckFrequencyFrame) Length(protocol.VersionNumber) protocol.ByteCount {
	return 1 + quicvarint.Len(f.SequenceNumber) + quicvarint.Len(f.PacketTolerance) + quicvarint.Len(uint64(f.UpdateMaxAckDelay/time.Microsecond)) + 1
}
