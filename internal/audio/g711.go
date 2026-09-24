// Package audio has the small amount of DSP SIPBXGO needs: G.711 (the codec
// every SIP phone speaks), generated hold music, WAV loading and mixing.
// Audio is 8 kHz mono 16-bit PCM throughout; a 20 ms frame is 160 samples.
package audio

// SampleRate is the telephone-band rate used everywhere in this package.
const SampleRate = 8000

// FrameSamples is one 20 ms packet of audio at SampleRate.
const FrameSamples = 160

// RTP static payload types for G.711.
const (
	PCMU = 0 // μ-law (North America, Japan)
	PCMA = 8 // A-law (rest of the world)
)

// G.711 per ITU-T, following the classic public-domain Sun reference code.

var (
	ulawDecode [256]int16
	alawDecode [256]int16
	segUEnd    = [8]int{0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF}
	segAEnd    = [8]int{0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF}
)

func init() {
	for i := 0; i < 256; i++ {
		ulawDecode[i] = ulaw2linear(byte(i))
		alawDecode[i] = alaw2linear(byte(i))
	}
}

func segment(v int, table *[8]int) int {
	for i, end := range table {
		if v <= end {
			return i
		}
	}
	return 8
}

// LinearToULaw encodes one sample to μ-law.
func LinearToULaw(sample int16) byte {
	const bias, clip = 0x84, 8159
	v := int(sample) >> 2
	mask := 0xFF
	if v < 0 {
		v, mask = -v, 0x7F
	}
	if v > clip {
		v = clip
	}
	v += bias >> 2
	seg := segment(v, &segUEnd)
	if seg >= 8 {
		return byte(0x7F ^ mask)
	}
	return byte(((seg << 4) | ((v >> (seg + 1)) & 0x0F)) ^ mask)
}

func ulaw2linear(u byte) int16 {
	const bias = 0x84
	u = ^u
	t := (int(u&0x0F) << 3) + bias
	t <<= (u & 0x70) >> 4
	if u&0x80 != 0 {
		return int16(bias - t)
	}
	return int16(t - bias)
}

// LinearToALaw encodes one sample to A-law.
func LinearToALaw(sample int16) byte {
	v := int(sample) >> 3
	mask := 0xD5
	if v < 0 {
		v, mask = -v-1, 0x55
	}
	seg := segment(v, &segAEnd)
	if seg >= 8 {
		return byte(0x7F ^ mask)
	}
	a := seg << 4
	if seg < 2 {
		a |= (v >> 1) & 0x0F
	} else {
		a |= (v >> seg) & 0x0F
	}
	return byte(a ^ mask)
}

func alaw2linear(a byte) int16 {
	a ^= 0x55
	t := int(a&0x0F) << 4
	switch seg := int(a&0x70) >> 4; seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t += 0x108
		t <<= seg - 1
	}
	if a&0x80 != 0 {
		return int16(t)
	}
	return int16(-t)
}

// Encode converts PCM to G.711 for payload type pt (PCMU or PCMA),
// appending to dst.
func Encode(dst []byte, pcm []int16, pt int) []byte {
	enc := LinearToULaw
	if pt == PCMA {
		enc = LinearToALaw
	}
	for _, s := range pcm {
		dst = append(dst, enc(s))
	}
	return dst
}

// Decode converts G.711 payload to PCM, appending to dst.
func Decode(dst []int16, payload []byte, pt int) []int16 {
	table := &ulawDecode
	if pt == PCMA {
		table = &alawDecode
	}
	for _, b := range payload {
		dst = append(dst, table[b])
	}
	return dst
}
