package audio

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestG711RoundTrip(t *testing.T) {
	for _, pt := range []int{PCMU, PCMA} {
		for _, v := range []int16{0, 1, -1, 100, -100, 1000, -1000, 8000, -8000, 32000, -32000, 32767, -32768} {
			got := Decode(nil, Encode(nil, []int16{v}, pt), pt)[0]
			// G.711 is logarithmic: error grows with amplitude but stays
			// within ~3% (plus a small floor near zero).
			tol := math.Max(16, math.Abs(float64(v))*0.035)
			if math.Abs(float64(got)-float64(v)) > tol {
				t.Errorf("pt %d: %d -> %d (tolerance %.0f)", pt, v, got, tol)
			}
		}
	}
	// Known reference values: silence encodes to 0xFF (μ-law) / 0xD5 (A-law).
	if LinearToULaw(0) != 0xFF || LinearToALaw(0) != 0xD5 {
		t.Errorf("silence: ulaw=%#x alaw=%#x", LinearToULaw(0), LinearToALaw(0))
	}
}

func TestHoldMusic(t *testing.T) {
	pcm := HoldMusic()
	secs := float64(len(pcm)) / SampleRate
	if secs < 15 || secs > 30 {
		t.Fatalf("loop is %.1fs", secs)
	}
	var peak float64
	var sum float64
	for _, s := range pcm {
		a := math.Abs(float64(s))
		peak = math.Max(peak, a)
		sum += a * a
	}
	rms := math.Sqrt(sum / float64(len(pcm)))
	if peak > 0.5*32767 || peak < 0.2*32767 {
		t.Errorf("peak %.0f outside the comfortable range", peak)
	}
	if rms < 500 {
		t.Errorf("rms %.0f: too quiet to hear on a phone", rms)
	}
	// The loop must end (and start) near silence so it repeats without a click.
	for _, s := range pcm[len(pcm)-80:] {
		if math.Abs(float64(s)) > 200 {
			t.Fatalf("loop ends at amplitude %d; would click on repeat", s)
		}
	}
}

// wav builds a PCM WAV file in memory.
func wav(rate, channels, bits int, frames [][]int) []byte {
	var data bytes.Buffer
	for _, f := range frames {
		for _, s := range f {
			if bits == 16 {
				binary.Write(&data, binary.LittleEndian, int16(s))
			} else {
				data.WriteByte(byte(s))
			}
		}
	}
	var b bytes.Buffer
	b.WriteString("RIFF")
	binary.Write(&b, binary.LittleEndian, uint32(36+data.Len()))
	b.WriteString("WAVEfmt ")
	binary.Write(&b, binary.LittleEndian, uint32(16))
	binary.Write(&b, binary.LittleEndian, uint16(1))
	binary.Write(&b, binary.LittleEndian, uint16(channels))
	binary.Write(&b, binary.LittleEndian, uint32(rate))
	binary.Write(&b, binary.LittleEndian, uint32(rate*channels*bits/8))
	binary.Write(&b, binary.LittleEndian, uint16(channels*bits/8))
	binary.Write(&b, binary.LittleEndian, uint16(bits))
	b.WriteString("LIST") // an unrelated chunk to skip
	binary.Write(&b, binary.LittleEndian, uint32(3))
	b.Write([]byte{1, 2, 3, 0}) // odd size + pad byte
	b.WriteString("data")
	binary.Write(&b, binary.LittleEndian, uint32(data.Len()))
	b.Write(data.Bytes())
	return b.Bytes()
}

func TestReadWAV(t *testing.T) {
	// 1 s of 44.1 kHz stereo: left 1000, right 3000 -> mono 2000 at 8 kHz.
	frames := make([][]int, 44100)
	for i := range frames {
		frames[i] = []int{1000, 3000}
	}
	pcm, err := ReadWAV(bytes.NewReader(wav(44100, 2, 16, frames)))
	if err != nil {
		t.Fatal(err)
	}
	if len(pcm) < 7990 || len(pcm) > 8010 {
		t.Fatalf("got %d samples, want ~8000", len(pcm))
	}
	if pcm[100] != 2000 {
		t.Errorf("downmix: got %d, want 2000", pcm[100])
	}

	// 8-bit mono at 8 kHz passes straight through (128 = silence).
	pcm, err = ReadWAV(bytes.NewReader(wav(8000, 1, 8, [][]int{{128}, {255}, {0}})))
	if err != nil || len(pcm) != 3 || pcm[0] != 0 || pcm[1] <= 0 || pcm[2] >= 0 {
		t.Fatalf("8-bit: %v %v", pcm, err)
	}

	if _, err := ReadWAV(bytes.NewReader([]byte("RIFF\x00\x00\x00\x00WAVX"))); err == nil {
		t.Error("accepted a non-WAV file")
	}
}
