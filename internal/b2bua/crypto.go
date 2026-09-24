package b2bua

import (
	"errors"
	"strings"

	"github.com/JustSparx/SIPBXGO/internal/media"
	"github.com/JustSparx/SIPBXGO/internal/sdp"
	"github.com/JustSparx/SIPBXGO/internal/store"
)

// SRTP is terminated at the PBX, separately on each side of a call: each
// phone exchanges keys only with the PBX (over TLS), and the relay decrypts
// and re-encrypts. A plain phone can therefore call an encrypted one, and
// later features (hold music, voicemail, conferences) can work on the audio.

var errNoUsableCrypto = errors.New("SRTP requested without a supported key")

// isTLS reports whether a transport name is SIP over TLS.
func isTLS(transport string) bool { return strings.EqualFold(transport, "TLS") }

// acceptOffer handles SDP a phone offered on side. It installs the phone's
// key for decrypting what it sends and returns the PBX key to put in the SDP
// answer to that phone (nil means plain RTP).
func (c *Call) acceptOffer(side int, info *sdp.Info) (*sdp.Crypto, error) {
	if !info.Secure {
		return nil, c.setCrypto(side, nil, nil)
	}
	if len(info.Cryptos) == 0 {
		return nil, errNoUsableCrypto
	}
	phone := info.Cryptos[0] // the phone's preference order
	c.mu.Lock()
	ours := c.keys[side]
	c.mu.Unlock()
	if ours == nil || ours.Suite != phone.Suite {
		var err error
		if ours, err = sdp.NewCrypto(phone.Tag, phone.Suite); err != nil {
			return nil, err
		}
	} else {
		// Same key, but the answer must echo the tag the phone chose.
		cp := *ours
		cp.Tag = phone.Tag
		ours = &cp
	}
	return ours, c.setCrypto(side, phone, ours)
}

// acceptAnswer handles a phone's SDP answer to an offer the PBX made with
// the key offered (nil if the offer was plain RTP).
func (c *Call) acceptAnswer(side int, info *sdp.Info, offered *sdp.Crypto) error {
	if offered == nil || !info.Secure {
		// A phone answering plain RTP to an SRTP offer is out of spec, but
		// plain audio beats no audio.
		return c.setCrypto(side, nil, nil)
	}
	for _, pc := range info.Cryptos {
		if pc.Tag == offered.Tag && pc.Suite == offered.Suite {
			return c.setCrypto(side, pc, offered)
		}
	}
	return errNoUsableCrypto
}

func (c *Call) setCrypto(side int, phone, ours *sdp.Crypto) error {
	if err := c.relay.SetCrypto(side, phone, ours); err != nil {
		return err
	}
	c.mu.Lock()
	if ours != nil {
		c.keys[side] = ours
	}
	c.secure[side] = ours != nil
	c.mu.Unlock()
	return nil
}

// offerKey is the PBX key to include in an offer to side, or nil for plain.
func (c *Call) offerKey(side int) *sdp.Crypto {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.secure[side] {
		return c.keys[side]
	}
	return nil
}

// Secure reports which sides of the call use SRTP.
func (c *Call) Secure() (caller, callee bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.secure[media.Caller], c.secure[media.Callee]
}

// Encryption summarizes the call: none, partial or full.
func (c *Call) Encryption() string {
	a, b := c.Secure()
	switch {
	case a && b:
		return store.EncryptionFull
	case a || b:
		return store.EncryptionPartial
	}
	return store.EncryptionNone
}
