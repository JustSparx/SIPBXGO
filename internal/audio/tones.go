package audio

import (
	"math"
	"time"
)

// Short signalling tones for conference rooms. No voice prompts: tones are
// universal, tiny, and need no recording or text-to-speech.
var (
	// PromptTone asks for the room PIN: two quick high beeps.
	PromptTone = Concat(tone(620, 120), Silence(80), tone(620, 120))
	// JoinTone plays to the room when someone arrives: a rising chime.
	JoinTone = Concat(tone(523, 110), tone(784, 170))
	// LeaveTone plays when someone leaves: a falling chime.
	LeaveTone = Concat(tone(784, 110), tone(523, 170))
	// ErrorTone signals a wrong PIN: three low buzzes.
	ErrorTone = Concat(tone(300, 150), Silence(80), tone(300, 150), Silence(80), tone(300, 150))
)

// tone is a sine of freq Hz for ms milliseconds with 5 ms fades (no clicks),
// at a level that sits comfortably alongside speech.
func tone(freq float64, ms int) []int16 {
	n := ms * SampleRate / 1000
	fade := 5 * SampleRate / 1000
	out := make([]int16, n)
	for i := range out {
		env := 1.0
		if i < fade {
			env = float64(i) / float64(fade)
		} else if n-i < fade {
			env = float64(n-i) / float64(fade)
		}
		out[i] = int16(0.3 * 32767 * env * math.Sin(2*math.Pi*freq*float64(i)/SampleRate))
	}
	return out
}

// Silence returns ms milliseconds of silence.
func Silence(ms int) []int16 { return make([]int16, ms*SampleRate/1000) }

// Concat joins sample slices.
func Concat(parts ...[]int16) []int16 {
	var out []int16
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// Duration of n samples.
func Duration(n int) time.Duration { return time.Duration(n) * time.Second / SampleRate }

// MixInto adds src into dst sample by sample with clipping.
func MixInto(dst, src []int16) {
	for i := range dst {
		if i >= len(src) {
			return
		}
		dst[i] = Clip(int32(dst[i]) + int32(src[i]))
	}
}

// Clip saturates a mixed sample to int16.
func Clip(v int32) int16 {
	switch {
	case v > math.MaxInt16:
		return math.MaxInt16
	case v < math.MinInt16:
		return math.MinInt16
	}
	return int16(v)
}
