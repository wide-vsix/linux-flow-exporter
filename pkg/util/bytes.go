package util

func BS16(v uint16) uint16 {
	v2 := uint16(0)
	v2 |= v<<8 | v>>8
	return v2
}

func BS32(v uint32) uint32 {
	v2 := uint32(0)
	v2 |= (0xff000000 & (v << 24)) | (0x00ff0000 & (v << 8)) | (0x0000ff00 & (v >> 8)) | (0x000000ff & (v >> 24))
	return v2
}
