package audio

import "math"

// HoldMusic synthesizes SIPBXGO's default hold music: a calm, looping
// electric-piano arpeggio over a I–vi–IV–V progression in C, with a slow
// melody on the second pass. Generated in code, so it is royalty-free by
// construction and costs nothing to ship.
//
// It is written for the telephone band: every note sits between ~260 Hz and
// ~1.3 kHz (phones cut off below ~300 Hz, so there's no real bass), notes
// have soft attacks and exponential decays, and the level leaves headroom so
// G.711 doesn't distort. The loop is ~19 s and ends in silence so it repeats
// without a click.
func HoldMusic() []int16 {
	const (
		bpm    = 100.0
		eighth = 60.0 / bpm / 2 // seconds
		bars   = 8
	)
	// MIDI note numbers. The chords sit an octave higher than written music
	// usually would, to stay inside the phone's passband.
	chords := [4][4]int{
		{60, 64, 67, 72}, // C
		{57, 60, 64, 69}, // Am
		{53, 57, 60, 65}, // F
		{55, 59, 62, 67}, // G
	}
	arp := []int{0, 1, 2, 3, 2, 1, 2, 1} // index into the chord, per eighth note
	// Melody for the second pass: (note, start eighth within the pass, length in eighths).
	melody := []struct{ note, at, len int }{
		{76, 0, 4}, {74, 4, 2}, {72, 6, 2},
		{72, 8, 4}, {69, 12, 4},
		{69, 16, 4}, {72, 20, 2}, {74, 22, 2},
		{74, 24, 6}, {71, 30, 2},
	}

	total := int(float64(bars*8)*eighth*SampleRate) + SampleRate // +1 s tail
	mix := make([]float64, total)

	for bar := 0; bar < bars; bar++ {
		chord := chords[bar%4]
		for step, idx := range arp {
			start := (float64(bar*8+step) * eighth)
			addNote(mix, chord[idx], start, eighth*3, 0.22)
		}
		// A soft sustained chord root under each bar.
		addPad(mix, chord[0], float64(bar*8)*eighth, eighth*8, 0.07)
	}
	passStart := float64(4*8) * eighth
	for _, m := range melody {
		addNote(mix, m.note, passStart+float64(m.at)*eighth, float64(m.len)*eighth*1.2, 0.18)
	}

	// Normalize to about -9 dBFS and convert.
	peak := 0.0
	for _, v := range mix {
		peak = math.Max(peak, math.Abs(v))
	}
	scale := 0.35 * 32767 / peak
	out := make([]int16, total)
	for i, v := range mix {
		out[i] = int16(v * scale)
	}
	return out
}

func midiFreq(n int) float64 { return 440 * math.Pow(2, float64(n-69)/12) }

// addNote mixes in a plucked, electric-piano-like tone: fundamental plus a
// little second and third harmonic, 8 ms attack, exponential decay.
func addNote(mix []float64, note int, start, dur, gain float64) {
	f := midiFreq(note)
	s0 := int(start * SampleRate)
	n := int(dur * SampleRate)
	for i := 0; i < n && s0+i < len(mix); i++ {
		t := float64(i) / SampleRate
		env := math.Min(1, t/0.008) * math.Exp(-3.2*t/dur)
		w := 2 * math.Pi * f * t
		mix[s0+i] += gain * env * (math.Sin(w) + 0.25*math.Sin(2*w) + 0.08*math.Sin(3*w))
	}
}

// addPad mixes in a slow-swelling sustained tone.
func addPad(mix []float64, note int, start, dur, gain float64) {
	f := midiFreq(note)
	s0 := int(start * SampleRate)
	n := int(dur * SampleRate)
	for i := 0; i < n && s0+i < len(mix); i++ {
		t := float64(i) / SampleRate
		env := math.Sin(math.Pi * t / dur) // fade in and out across the bar
		mix[s0+i] += gain * env * math.Sin(2*math.Pi*f*t)
	}
}
