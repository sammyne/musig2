package sr25519

import "errors"

// ErrUnmarshalPublicKey signals public key unmarshaling failed.
var ErrUnmarshalPublicKey = errors.New("unmarshal public key")
