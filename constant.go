package musig2

//go:generate stringer -type State -trimprefix State

type State uint8

const (
	StateUnknown State = iota
	StateNew
	StateNonceCollecting // collecting nonces
	StateCosigning       // generate and collect partial sig
	StateCosigned        // all partial sig have been collected
	StateSigned          // aggregate sig
)

const (
	SigningCtxLabel = "SigningContext"
)

const (
	CosigLen = 64
	// NoncesLen specify the total nonces for each party to use.
	NoncesLen = 2
)

const noncesBytesLen = NoncesLen * 32
