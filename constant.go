package musig

type State uint8

const (
	StateUnknown State = iota
	StateCommit        // generate and collect commitments
	StateReveal        // reveal and collect commitments
	StateCosign        // generate partial sig
	StateSign          // aggregate partial sig into final sig
)

const (
	SigningCtxLabel = "SigningContext"
)

const Rewinds = 4
