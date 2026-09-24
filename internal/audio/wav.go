package audio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// LoadWAV reads a PCM WAV file (8- or 16-bit, mono or stereo, any sample
// rate) and returns it as 8 kHz mono 16-bit samples, for custom hold music.
func LoadWAV(path string) ([]int16, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ReadWAV(f)
}

// ReadWAV is LoadWAV for an open reader.
func ReadWAV(r io.Reader) ([]int16, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("wav: %w", err)
	}
	if string(hdr[0:4]) != "RIFF" || string(hdr[8:12]) != "WAVE" {
		return nil, errors.New("wav: not a RIFF/WAVE file")
	}

	var (
		format, channels, bits uint16
		rate                   uint32
		haveFmt                bool
	)
	for {
		var ch [8]byte
		if _, err := io.ReadFull(r, ch[:]); err != nil {
			return nil, errors.New("wav: no data chunk")
		}
		id, size := string(ch[0:4]), binary.LittleEndian.Uint32(ch[4:8])
		switch id {
		case "fmt ":
			if size < 16 {
				return nil, errors.New("wav: short fmt chunk")
			}
			b := make([]byte, size+size%2)
			if _, err := io.ReadFull(r, b); err != nil {
				return nil, err
			}
			format = binary.LittleEndian.Uint16(b[0:])
			channels = binary.LittleEndian.Uint16(b[2:])
			rate = binary.LittleEndian.Uint32(b[4:])
			bits = binary.LittleEndian.Uint16(b[14:])
			haveFmt = true
		case "data":
			if !haveFmt {
				return nil, errors.New("wav: data before fmt")
			}
			if format != 1 && format != 0xFFFE {
				return nil, fmt.Errorf("wav: only uncompressed PCM is supported (format %d)", format)
			}
			if bits != 8 && bits != 16 {
				return nil, fmt.Errorf("wav: %d-bit audio not supported (use 8 or 16)", bits)
			}
			if channels == 0 || rate == 0 {
				return nil, errors.New("wav: bad format")
			}
			if size > 64<<20 {
				return nil, errors.New("wav: file too large for hold music")
			}
			data := make([]byte, size)
			if _, err := io.ReadFull(r, data); err != nil {
				return nil, fmt.Errorf("wav: %w", err)
			}
			return resample(toMono(data, int(channels), int(bits)), int(rate)), nil
		default:
			if _, err := io.CopyN(io.Discard, r, int64(size+size%2)); err != nil {
				return nil, errors.New("wav: truncated")
			}
		}
	}
}

func toMono(data []byte, channels, bits int) []float64 {
	width := bits / 8
	frames := len(data) / (width * channels)
	out := make([]float64, frames)
	for i := range out {
		sum := 0.0
		for c := 0; c < channels; c++ {
			off := (i*channels + c) * width
			if bits == 16 {
				sum += float64(int16(binary.LittleEndian.Uint16(data[off:])))
			} else {
				sum += (float64(data[off]) - 128) * 256
			}
		}
		out[i] = sum / float64(channels)
	}
	return out
}

// resample converts to 8 kHz. Downsampling averages each output sample's
// window first, a crude low-pass that keeps music from aliasing badly.
func resample(in []float64, rate int) []int16 {
	if rate == SampleRate {
		return clip(in)
	}
	ratio := float64(rate) / SampleRate
	n := int(float64(len(in)) / ratio)
	out := make([]float64, n)
	for i := range out {
		lo := float64(i) * ratio
		hi := lo + ratio
		if ratio <= 1 { // upsampling: linear interpolation
			j := int(lo)
			frac := lo - float64(j)
			a, b := in[j], in[j]
			if j+1 < len(in) {
				b = in[j+1]
			}
			out[i] = a + (b-a)*frac
			continue
		}
		sum, cnt := 0.0, 0
		for j := int(lo); j < int(hi) && j < len(in); j++ {
			sum += in[j]
			cnt++
		}
		if cnt > 0 {
			out[i] = sum / float64(cnt)
		}
	}
	return clip(out)
}

func clip(in []float64) []int16 {
	out := make([]int16, len(in))
	for i, v := range in {
		switch {
		case v > 32767:
			out[i] = 32767
		case v < -32768:
			out[i] = -32768
		default:
			out[i] = int16(v)
		}
	}
	return out
}
