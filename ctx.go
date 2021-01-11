package musig

import "github.com/sammyne/merlin"

// ctx will be modified in place.
func NewSigningCtx(ctx []byte) *merlin.Transcript {
	t := merlin.NewTranscript([]byte(SigningCtxLabel))
	t.AppendMessage(nil, ctx)

	return t
}
