package dns

import (
	"os"
	"io"
	"fmt"
	"encoding/binary"
)

func writeLabel(w io.Writer, label string) os.Error {
	l := len(label)
	if l >= 256 {
		return fmt.Errorf("Label %s too long", label)
	}
	er := binary.Write(w, binary.BigEndian, byte(l))
	if er != nil {
		return er
	}
	_, er = w.Write([]byte(label))
	return er
}

func readLabels(r packetReader) (labels []string, er os.Error) {
	labels = make([]string, 0)

	for {
		var b byte
		er = binary.Read(r.buf, binary.BigEndian, &b)
		switch true {
		case er != nil:
			return nil, er
		case b == 0:
			return labels, nil
		case b < 64:
			x := make([]byte, b)
			_, er := r.buf.Read(x[:])
			if er != nil {
				return nil, er
			}
			labels = append(labels, string(x))
		case (b & 0300) == 0300:
			// pointer to a string of labels
			var b2 byte
			binary.Read(r.buf, binary.BigEndian, &b2)
			offset := int(b&077)<<8 + int(b2)
			r2 := newPacketReader(r.packet)
			r2.buf.Next(offset)
			labels2, er := readLabels(r2)
			return append(labels, labels2...), er
		default:
			return nil, os.NewError("Invalid label specification")
		}
	}
	panic("Unreachable")
}
