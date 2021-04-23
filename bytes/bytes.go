package bytes

// Copy makes a deep copy of x.
func Copy(x []byte) []byte {
	return append([]byte(nil), x...)
}
