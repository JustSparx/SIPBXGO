// Package sdp does the minimal SDP work a media-relaying B2BUA needs: read
// where a phone wants audio sent, and rewrite a body so audio flows through
// the relay instead.
//
// It edits line by line rather than round-tripping through a full SDP model,
// so codec lists, fmtp/ptime and vendor attributes from phones pass through
// byte-for-byte, and quirky-but-harmless SDP from cheap phones never breaks a call.
package sdp

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
)

var ErrNoAudio = errors.New("sdp: no audio stream")

// Info is what the relay needs to know about one side's SDP.
type Info struct {
	// Addr is the audio connection address (media-level c= if present,
	// otherwise session-level). Unspecified (0.0.0.0) means "on hold".
	Addr netip.Addr
	// Port is the audio RTP port; 0 means the stream is disabled.
	Port int
	// RTCPPort is from a=rtcp if present, otherwise Port+1.
	RTCPPort int
	// Direction is sendrecv, sendonly, recvonly or inactive.
	Direction string
	// Secure is true when the audio profile is SRTP (RTP/SAVP or RTP/SAVPF).
	Secure bool
	// Cryptos are the usable SDES keys offered for audio, in preference order.
	Cryptos []*Crypto
	// Formats are the audio payload types from the m= line, in preference order.
	Formats []int
}

// G711 returns the phone's preferred G.711 payload type (0 = PCMU,
// 8 = PCMA) for audio the PBX generates itself, defaulting to PCMU.
func (i *Info) G711() int {
	for _, pt := range i.Formats {
		if pt == 0 || pt == 8 {
			return pt
		}
	}
	return 0
}

// OnHold reports whether this SDP puts the call on hold, in either the old
// (c=0.0.0.0) or modern (a=sendonly / a=inactive) style.
func (i *Info) OnHold() bool {
	return i.Addr.IsUnspecified() || i.Direction == "sendonly" || i.Direction == "inactive"
}

// Parse extracts the first audio stream's address and ports.
func Parse(body []byte) (*Info, error) {
	var (
		sessionAddr, mediaAddr netip.Addr
		sessionDir, mediaDir   string
		inAudio, found, done   bool
		seenM                  bool // past the session-level section
		info                   Info
	)
	for _, line := range lines(body) {
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		if strings.HasPrefix(line, "m=") {
			seenM = true
			if found {
				done = true // only the first audio stream matters
			}
			inAudio = false
			if !done && strings.HasPrefix(line, "m=audio ") {
				f := strings.Fields(line)
				if len(f) < 4 {
					return nil, errors.New("sdp: malformed m= line")
				}
				port, err := strconv.Atoi(strings.SplitN(f[1], "/", 2)[0])
				if err != nil {
					return nil, errors.New("sdp: bad audio port")
				}
				info.Port, inAudio, found = port, true, true
				info.Secure = strings.Contains(f[2], "SAVP")
				for _, v := range f[3:] {
					if pt, err := strconv.Atoi(v); err == nil {
						info.Formats = append(info.Formats, pt)
					}
				}
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "c="):
			addr, ok := connAddr(line)
			if !ok {
				continue
			}
			if !seenM {
				sessionAddr = addr
			} else if inAudio {
				mediaAddr = addr
			}
		case strings.HasPrefix(line, "a=crypto:") && inAudio:
			if c, err := parseCrypto(strings.TrimPrefix(line, "a=crypto:")); err == nil && c != nil {
				info.Cryptos = append(info.Cryptos, c)
			}
		case strings.HasPrefix(line, "a=rtcp:") && inAudio:
			f := strings.Fields(strings.TrimPrefix(line, "a=rtcp:"))
			if len(f) > 0 {
				if p, err := strconv.Atoi(f[0]); err == nil {
					info.RTCPPort = p
				}
			}
		case line == "a=sendrecv" || line == "a=sendonly" || line == "a=recvonly" || line == "a=inactive":
			dir := line[2:]
			if !seenM {
				sessionDir = dir
			} else if inAudio {
				mediaDir = dir
			}
		}
	}
	if !found {
		return nil, ErrNoAudio
	}
	info.Addr = sessionAddr
	if mediaAddr.IsValid() {
		info.Addr = mediaAddr
	}
	if !info.Addr.IsValid() {
		return nil, errors.New("sdp: no connection address for audio")
	}
	info.Direction = "sendrecv"
	if sessionDir != "" {
		info.Direction = sessionDir
	}
	if mediaDir != "" {
		info.Direction = mediaDir
	}
	if info.RTCPPort == 0 && info.Port != 0 {
		info.RTCPPort = info.Port + 1
	}
	return &info, nil
}

// Rewrite returns body with audio redirected to ip:port (RTCP to port+1).
//   - o= and c= addresses become ip, except c=0.0.0.0 which is kept so
//     old-style hold still means hold to the other phone.
//   - The first audio m= line gets port (unless it was 0 = disabled).
//   - Other media streams (video, etc.) are disabled with port 0; the relay
//     only carries audio.
//   - With crypto set, audio becomes SRTP (RTP/SAVP) keyed with it; with
//     crypto nil it becomes plain RTP/AVP. The phone's own a=crypto lines
//     never pass through: each side of the relay has its own keys.
//   - ICE, DTLS and ZRTP attributes are dropped: the relay is the only
//     candidate and terminates any encryption itself.
func Rewrite(body []byte, ip netip.Addr, port int, crypto *Crypto) ([]byte, error) {
	if _, err := Parse(body); err != nil {
		return nil, err
	}
	addrType := "IP4"
	if ip.Is6() && !ip.Is4In6() {
		addrType = "IP6"
	}
	ipStr := ip.Unmap().String()

	var out strings.Builder
	write := func(line string) {
		out.WriteString(line)
		out.WriteString("\r\n")
	}
	inAudio, audioSeen := false, false
	endAudio := func() {
		if inAudio && crypto != nil {
			write("a=" + crypto.String())
		}
		inAudio = false
	}
	for _, line := range lines(body) {
		switch {
		case strings.HasPrefix(line, "o="):
			f := strings.Fields(line)
			if len(f) == 6 {
				f[4], f[5] = addrType, ipStr
				line = strings.Join(f, " ")
			}
		case strings.HasPrefix(line, "c="):
			if addr, ok := connAddr(line); ok && !addr.IsUnspecified() {
				line = "c=IN " + addrType + " " + ipStr
			}
		case strings.HasPrefix(line, "m="):
			endAudio()
			f := strings.Fields(line)
			if len(f) >= 3 {
				if f[0] == "m=audio" && !audioSeen {
					audioSeen, inAudio = true, true
					if f[1] != "0" {
						f[1] = strconv.Itoa(port)
					}
					f[2] = audioProto(f[2], crypto != nil)
				} else {
					f[1] = "0"
				}
				line = strings.Join(f, " ")
			}
		case strings.HasPrefix(line, "a=rtcp:"):
			if !inAudio {
				continue
			}
			line = "a=rtcp:" + strconv.Itoa(port+1) + " IN " + addrType + " " + ipStr
		case strings.HasPrefix(line, "a=candidate:"), strings.HasPrefix(line, "a=ice-"),
			line == "a=end-of-candidates", line == "a=rtcp-mux",
			strings.HasPrefix(line, "a=crypto:"), strings.HasPrefix(line, "a=fingerprint:"),
			strings.HasPrefix(line, "a=setup:"), strings.HasPrefix(line, "a=zrtp-hash:"):
			// rtcp-mux is dropped too: the relay keeps RTCP on port+1.
			continue
		}
		write(line)
	}
	endAudio()
	return []byte(out.String()), nil
}

// audioProto maps a transport profile to plain or SRTP, keeping feedback
// (AVPF) if the phone asked for it. DTLS profiles become plain SDES/RTP.
func audioProto(proto string, secure bool) string {
	feedback := strings.HasSuffix(proto, "AVPF")
	switch {
	case secure && feedback:
		return "RTP/SAVPF"
	case secure:
		return "RTP/SAVP"
	case feedback:
		return "RTP/AVPF"
	default:
		return "RTP/AVP"
	}
}

// lines splits on LF, tolerating CRLF and trailing whitespace.
func lines(body []byte) []string {
	raw := strings.Split(string(body), "\n")
	out := raw[:0]
	for _, l := range raw {
		l = strings.TrimRight(l, "\r \t")
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// connAddr parses "c=IN IP4 1.2.3.4" (ignoring any /ttl suffix).
func connAddr(line string) (netip.Addr, bool) {
	f := strings.Fields(strings.TrimPrefix(line, "c="))
	if len(f) < 3 {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(strings.SplitN(f[2], "/", 2)[0])
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// AnswerDirection is the direction to answer an offer with: the mirror image
// of the offer's (sendonly <-> recvonly).
func AnswerDirection(offer string) string {
	switch offer {
	case "sendonly":
		return "recvonly"
	case "recvonly":
		return "sendonly"
	case "inactive":
		return "inactive"
	}
	return "sendrecv"
}

// SetDirection returns body with the audio stream's direction attribute set
// to dir, replacing any session- or media-level direction.
func SetDirection(body []byte, dir string) []byte {
	var out strings.Builder
	inAudio, placed := false, false
	flush := func() {
		if inAudio && !placed {
			out.WriteString("a=" + dir + "\r\n")
			placed = true
		}
	}
	for _, line := range lines(body) {
		switch {
		case line == "a=sendrecv" || line == "a=sendonly" || line == "a=recvonly" || line == "a=inactive":
			continue
		case strings.HasPrefix(line, "m="):
			flush()
			inAudio = strings.HasPrefix(line, "m=audio ") && !placed
		}
		out.WriteString(line + "\r\n")
	}
	flush()
	return []byte(out.String())
}

// BumpVersion returns body with the o= line's session version incremented,
// as RFC 3264 requires whenever a party changes its session description.
func BumpVersion(body []byte) []byte {
	var out strings.Builder
	for _, line := range lines(body) {
		if strings.HasPrefix(line, "o=") {
			if f := strings.Fields(line); len(f) == 6 {
				if v, err := strconv.ParseUint(f[2], 10, 64); err == nil {
					f[2] = strconv.FormatUint(v+1, 10)
					line = strings.Join(f, " ")
				}
			}
		}
		out.WriteString(line + "\r\n")
	}
	return []byte(out.String())
}
