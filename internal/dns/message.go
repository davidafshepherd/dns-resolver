package dns

// Constants for DNS message fields.
const (
	QR       uint16 = 0x8000
	RD       uint16 = 0x0100
	QTypeA   uint16 = 1
	QClassIN uint16 = 1
)

// Message represents a DNS message.
type Message struct {
	Header      Header
	Question    Question
	Answers     []ResourceRecord
	Authorities []ResourceRecord
	Additionals []ResourceRecord
}

// Header represents a DNS header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question represents a DNS question.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ResourceRecord represents a DNS resource record.
type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}
