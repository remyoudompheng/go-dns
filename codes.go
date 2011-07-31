package dns

// message types
const (
	TypeQuery    = 0
	TypeResponse = 1 << 15
)

// op codes
const (
	OpQuery  = 0
	OpIQuery = 1 << 11
	OpStatus = 2 << 11
)

const (
	FlagAuthoritative = 1 << 10
	FlagTruncated     = 1 << 9
	FlagRecDesired    = 1 << 8
	FlagRecursive     = 1 << 7
)

// Response codes
const (
	RespOK             = 0
	RespFmtError       = 1
	RespServfail       = 2
	RespNameError      = 3
	RespNotImplemented = 4
	RespRefused        = 5
)

const (
	ClassA     = 1
	ClassNS    = 2
	ClassCNAME = 5
	ClassMX    = 15
)

const (
	ClassIN = 1
)
