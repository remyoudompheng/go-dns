package dns

import (
  "bytes"
)

type packetReader struct {
  buf *bytes.Buffer
  packet []byte
}

func newPacketReader(packet []byte) packetReader {
  var p packetReader
  p.buf = bytes.NewBuffer(packet)
  p.packet = packet
  return p
}
