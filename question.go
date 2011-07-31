package dns

import (
	"os"
	"io"
	"encoding/binary"
)

type Question struct {
	Name  []string
	Type  uint16
	Class uint16
}

// Writes a question in wire format
func (q *Question) Write(w io.Writer) os.Error {
	for _, label := range q.Name {
		er := writeLabel(w, label)
		if er != nil {
			return er
		}
	}
	er := writeLabel(w, "")
	if er != nil {
		return er
	}
	er = binary.Write(w, binary.BigEndian, q.Type)
	if er != nil {
		return er
	}
	er = binary.Write(w, binary.BigEndian, q.Class)
	return er
}

func ReadQuestion(r packetReader) (q Question, er os.Error) {
	q.Name, er = readLabels(r)
	if er != nil {
		return q, er
	}

	er = binary.Read(r.buf, &binary.BigEndian, &q.Type)
	if er != nil {
		return q, er
	}
	er = binary.Read(r.buf, &binary.BigEndian, &q.Class)
	return q, er
}

func readQuestions(r packetReader, n uint16) (q []Question, er os.Error) {
	q = make([]Question, n)
	for i := uint16(0); i < n; i++ {
		q[i], er = ReadQuestion(r)
		if er != nil {
			return nil, er
		}
	}
	return q, er
}

type RR struct {
	Query Question
	TTL   uint32
	RData []byte
}

// Write a Resource Record in wire format
func (r *RR) Write(w io.Writer) os.Error {
	er := r.Query.Write(w)
	if er != nil {
		return er
	}

	er = binary.Write(w, binary.BigEndian, r.TTL)
	if er != nil {
		return er
	}

	// Write 16-bit length + data
	rLength := uint16(len(r.RData))
	er = binary.Write(w, binary.BigEndian, rLength)
	if er != nil {
		return er
	}
	_, er = w.Write(r.RData)
	return er
}

func readRecord(r packetReader) (rec RR, er os.Error) {
	// read question
	rec.Query, er = ReadQuestion(r)
	if er != nil {
		return rec, er
	}

	// read data
	er = binary.Read(r.buf, binary.BigEndian, &rec.TTL)
	if er != nil {
		return rec, er
	}

	var l uint16
	er = binary.Read(r.buf, binary.BigEndian, &l)
	if er != nil {
		return rec, er
	}

	rec.RData = make([]byte, l)
	_, er = r.buf.Read(rec.RData)
	return rec, er
}

func readRecords(r packetReader, n uint16) (recs []RR, er os.Error) {
	recs = make([]RR, n)
	var i uint16
	for i = 0; i < n; i++ {
		recs[i], er = readRecord(r)
		if er != nil {
			return nil, er
		}
	}
	return recs, er
}
