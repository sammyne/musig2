package bytes

func Copy(x []byte) []byte {
	return append([]byte(nil), x...)
}
