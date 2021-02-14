package musig2

import "errors"

var (
	ErrBadNonces            = errors.New("bad nonces")
	ErrBadSig               = errors.New("bad sig")
	ErrDecodeReveal         = errors.New("invalid reveal")
	ErrDoubleCache          = errors.New("entry is duplicate cache")
	ErrGenerateChallenge    = errors.New("generate challenge")
	ErrInvalidState         = errors.New("invalid state")
	ErrInvalidCosig         = errors.New("invalid co-sig")
	ErrRand                 = errors.New("rand")
	ErrRevealMismatchCommit = errors.New("reveal doesn't match commitment")
	ErrUnknownPK            = errors.New("unknown public key")
)
