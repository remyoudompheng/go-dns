package dns

import (
	"io"
	"os"
  "bytes"
	"encoding/binary"
)

// This package implements the DNS message format (RFC1035)

type DnsMessage struct {
	ID                 uint16
	MsgType            uint16 // 0 is query, 1 is response
	Opcode             uint16
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	RespCode           uint16

	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

// Reads a raw DNS message from a Reader
func parseMessage(r packetReader) (msg DnsMessage, er os.Error) {
	// Message ID
	er = binary.Read(r.buf, binary.BigEndian, &msg.ID)
	if er != nil {
		return msg, er
	}
	// Message flags
	var flags uint16
	er = binary.Read(r.buf, binary.BigEndian, &flags)
	msg.MsgType = flags & (1 << 15)
	msg.Opcode = flags & (0xf << 11)
	msg.Authoritative = (flags & (1 << 10)) != 0
	msg.Truncated = (flags & (1 << 9)) != 0
	msg.RecursionDesired = (flags & (1 << 8)) != 0
	msg.RecursionAvailable = (flags & (1 << 7)) != 0
	msg.RespCode = flags & 0x0f

	// Data
	var counts [4]uint16
	er = binary.Read(r.buf, binary.BigEndian, counts[:])
	if er != nil {
		return msg, er
	}

	// Questions
	msg.Questions, er = readQuestions(r, counts[0])
	if er != nil {
		return msg, er
	}
	msg.Answers, er = readRecords(r, counts[1])
	if er != nil {
		return msg, er
	}
	msg.Authority, er = readRecords(r, counts[2])
	if er != nil {
		return msg, er
	}
	msg.Additional, er = readRecords(r, counts[3])
	return msg, er
}

// Decodes a DNS packet
func DecodeMessage(packet []byte) (msg *DnsMessage, er os.Error) {
  reader := newPacketReader(packet)
  m, er := parseMessage(reader)
  return &m, er
}

// Reads a DNS packet from a reader (usually a network connection)
func RecvMessage(r io.Reader) (msg *DnsMessage, er os.Error) {
  packet := make([]byte, 512)
  length, er := r.Read(packet[:])
  if er != nil { return nil, er }
  return DecodeMessage(packet[:length])
}

func (msg DnsMessage) write(w io.Writer) os.Error {
	// message ID
	er := binary.Write(w, binary.BigEndian, msg.ID)
	if er != nil {
		return er
	}
	// message flags
	var flags uint16
	flags = msg.MsgType | msg.Opcode | msg.RespCode
	if msg.Authoritative {
		flags |= FlagAuthoritative
	}
	if msg.Truncated {
		flags |= FlagTruncated
	}
	if msg.RecursionDesired {
		flags |= FlagRecDesired
	}
	er = binary.Write(w, binary.BigEndian, flags)

	// Item counts
	count := uint16(len(msg.Questions))
	er = binary.Write(w, binary.BigEndian, count)
	count = uint16(len(msg.Answers))
	er = binary.Write(w, binary.BigEndian, count)
	count = uint16(len(msg.Authority))
	er = binary.Write(w, binary.BigEndian, count)
	count = uint16(len(msg.Additional))
	er = binary.Write(w, binary.BigEndian, count)

	// Data
	for _, q := range msg.Questions {
		er = q.Write(w)
	}
	for _, r := range msg.Answers {
		er = r.Write(w)
	}
	for _, r := range msg.Authority {
		er = r.Write(w)
	}
	for _, r := range msg.Additional {
		er = r.Write(w)
	}

	return er
}

// Writes a DNS message in wire format
func (msg *DnsMessage)SendMessage(w io.Writer) os.Error {
  buf := bytes.NewBuffer(nil)
  msg.write(buf)
  _, er := w.Write(buf.Bytes())
  return er
}


