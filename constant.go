package musig

//go:generate stringer -type State -trimprefix State

type State uint8

const (
	StateUnknown State = iota
	StateNew
	StateCommit // generate and collect commitments
	StateReveal // reveal and collect commitments
	StateCosign // generate partial sig
	StateSign   // aggregate partial sig into final sig
)

const (
	SigningCtxLabel = "SigningContext"
)

const (
	CosigLen = 64
	Rewinds  = 4
)
