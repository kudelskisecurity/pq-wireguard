/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kudelskisecurity/wireguard/tai64n"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/sha3"
)

type handshakeState int

// TODO(crawshaw): add commentary describing each state and the transitions
const (
	handshakeZeroed = handshakeState(iota)
	handshakeInitiationCreated
	handshakeInitiationConsumed
	handshakeResponseCreated
	handshakeResponseConsumed
)

func (hs handshakeState) String() string {
	switch hs {
	case handshakeZeroed:
		return "handshakeZeroed"
	case handshakeInitiationCreated:
		return "handshakeInitiationCreated"
	case handshakeInitiationConsumed:
		return "handshakeInitiationConsumed"
	case handshakeResponseCreated:
		return "handshakeResponseCreated"
	case handshakeResponseConsumed:
		return "handshakeResponseConsumed"
	default:
		return fmt.Sprintf("Handshake(UNKNOWN:%d)", int(hs))
	}
}

const (
	NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	WGIdentifier      = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	WGLabelMAC1       = "mac1----"
	WGLabelCookie     = "cookie--"
	PlaceHolder       = 32
)

const (
	MessageInitiationType  = 1
	MessageResponseType    = 2
	MessageCookieReplyType = 3
	MessageTransportType   = 4
)

const (
	MessageInitiationSize      = 2*4 + sizeCPAKyberPK + blake2s.Size + poly1305.TagSize + tai64n.TimestampSize + poly1305.TagSize + sizeCCAKyberC + 2*blake2s.Size128 //2388                                          // size of handshake initiation message ere add SIZEC
	MessageResponseSize        = 3*4 + sizeCCAKyberC + sizeCPAKyberC + poly1305.TagSize + 2*blake2s.Size128                                                           //2260                                                                                                     //92 + 2*utils.SIZEC                            // size of response message
	MessageCookieReplySize     = 64                                                                                                                                   // size of cookie reply message
	MessageTransportHeaderSize = 16                                                                                                                                   // size of data preceding content in transport message
	MessageTransportSize       = MessageTransportHeaderSize + poly1305.TagSize                                                                                        // size of empty transport
	MessageKeepaliveSize       = MessageTransportSize                                                                                                                 // size of keepalive
	MessageHandshakeSize       = MessageInitiationSize                                                                                                                // size of largest handshake related message
)

const (
	MessageTransportOffsetReceiver = 4
	MessageTransportOffsetCounter  = 8
	MessageTransportOffsetContent  = 16
)

/* Type is an 8-bit field, followed by 3 nul bytes,
 * by marshalling the messages in little-endian byteorder
 * we can treat these as a 32-bit unsigned int (for now)
 *
 */

type MessageInitiation struct {
	Type      uint32
	Sender    uint32
	Ephemeral CPAKyberPK
	Static    [blake2s.Size + poly1305.TagSize]byte
	Timestamp [tai64n.TimestampSize + poly1305.TagSize]byte
	Ct1       [sizeCCAKyberC]byte
	MAC1      [blake2s.Size128]byte
	MAC2      [blake2s.Size128]byte
}

type MessageResponse struct {
	Type     uint32
	Sender   uint32
	Receiver uint32
	Ct2      [sizeCPAKyberC]byte
	Ct3      [sizeCCAKyberC]byte
	Empty    [poly1305.TagSize]byte
	MAC1     [blake2s.Size128]byte
	MAC2     [blake2s.Size128]byte
}

type MessageTransport struct {
	Type     uint32
	Receiver uint32
	Counter  uint64
	Content  []byte
}

type MessageCookieReply struct {
	Type     uint32
	Receiver uint32
	Nonce    [chacha20poly1305.NonceSizeX]byte
	Cookie   [blake2s.Size128 + poly1305.TagSize]byte //here
}

type Handshake struct {
	state           handshakeState
	mutex           sync.RWMutex
	hash            [blake2s.Size]byte // hash value
	chainKey        [blake2s.Size]byte // chain key
	presharedKey    [blake2s.Size]byte // H(psk)
	localEphemeral  CPAKyberSK         // ephemeral secret key kyber PKE ske
	localIndex      uint32             // used to clear hash-table
	remoteIndex     uint32             // index for sending
	remoteStatic    CCAKyberPK         // long term key
	remoteEphemeral CPAKyberPK         // ephemeral public key
	//precomputedStaticStatic   [PlaceHolder]byte  // precomputed shared secret
	lastTimestamp             tai64n.Timestamp
	lastInitiationConsumption time.Time
	lastSentHandshake         time.Time
}

var (
	InitialChainKey [blake2s.Size]byte
	InitialHash     [blake2s.Size]byte
	ZeroNonce       [chacha20poly1305.NonceSize]byte
)

func mixKey(dst *[blake2s.Size]byte, c *[blake2s.Size]byte, data []byte) {
	KDF1(dst, c[:], data)
}

func mixHash(dst *[blake2s.Size]byte, h *[blake2s.Size]byte, data []byte) {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func (h *Handshake) Clear() {
	setZero(h.localEphemeral[:])
	setZero(h.remoteEphemeral[:])
	setZero(h.chainKey[:])
	setZero(h.hash[:])
	h.localIndex = 0
	h.state = handshakeZeroed
}

func (h *Handshake) mixHash(data []byte) {
	mixHash(&h.hash, &h.hash, data)
}

func (h *Handshake) mixKey(data []byte) {
	mixKey(&h.chainKey, &h.chainKey, data)
}

/* Do basic precomputations
 */
func init() {
	InitialChainKey = blake2s.Sum256([]byte(NoiseConstruction))
	mixHash(&InitialHash, &InitialChainKey, []byte(WGIdentifier))
}

func (device *Device) CreateMessageInitiation(peer *Peer) (*MessageInitiation, error) {
	//var errZeroECDHResult = errors.New("AKE returned all zeros")

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()

	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// create ephemeral key
	var err error
	handshake.hash = InitialHash
	handshake.chainKey = InitialChainKey
	pk, sk := cpaKyber.CPAKeyGen()
	var bsk CPAKyberSK
	copy(bsk[:], sk)
	var bpk CPAKyberPK
	copy(bpk[:], pk)

	handshake.localEphemeral = bsk
	if err != nil {
		return nil, err
	}

	var ri [4]byte
	rand.Read(ri[:])

	encSeed := sha3.Sum256(append(device.staticIdentity.sigma, ri[:]...))
	//KDF1(encSeed[:blake2s.Size], device.staticIdentity.sigma, ri[:])
	ct1, shk1 := ccaKyber.Encaps(handshake.remoteStatic[:], encSeed[:])
	msg := MessageInitiation{
		Type:      MessageInitiationType,
		Ephemeral: bpk,
	}
	copy(msg.Ct1[:], ct1[:])

	handshake.mixKey(msg.Ephemeral[:])
	//C2
	chainKey := &handshake.chainKey //== C2

	handshake.mixHash(handshake.remoteStatic[:])
	//H2
	handshake.mixHash(msg.Ephemeral[:])
	//H3

	var key [chacha20poly1305.KeySize]byte
	KDF2(&handshake.chainKey, &key, handshake.chainKey[:], shk1)
	//chainKey == C3
	//key == k3

	aead, _ := chacha20poly1305.New(key[:])
	hpki := blake2s.Sum256(device.staticIdentity.publicKey[:])
	aead.Seal(msg.Static[:0], ZeroNonce[:], hpki[:], handshake.hash[:])

	handshake.mixHash(msg.Static[:])
	//H4

	// encrypt timestamp

	KDF2(chainKey, &key, chainKey[:], handshake.presharedKey[:])
	//key == k4
	handshake.mixKey(handshake.presharedKey[:])
	//chainKey == C4
	timestamp := tai64n.Now()
	aead, _ = chacha20poly1305.New(key[:])
	aead.Seal(msg.Timestamp[:0], ZeroNonce[:], timestamp[:], handshake.hash[:])

	// assign index
	device.indexTable.Delete(handshake.localIndex)
	msg.Sender, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}
	handshake.localIndex = msg.Sender

	handshake.mixHash(msg.Timestamp[:])
	//H5

	handshake.state = handshakeInitiationCreated
	return &msg, nil

	//at the end, chainkey is C4 and hash is H5
}

func (device *Device) ConsumeMessageInitiation(msg *MessageInitiation) *Peer {
	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	if msg.Type != MessageInitiationType {
		return nil
	}

	device.staticIdentity.RLock()
	defer device.staticIdentity.RUnlock()
	mixHash(&hash, &InitialHash, device.staticIdentity.publicKey[:])
	//H2
	mixHash(&hash, &hash, msg.Ephemeral[:])
	//H3
	mixKey(&chainKey, &InitialChainKey, msg.Ephemeral[:])
	//C2

	C2 := &chainKey

	// decrypt static key
	var err error
	var hpeerPK [blake2s.Size]byte
	var key [chacha20poly1305.KeySize]byte
	shk1 := ccaKyber.Decaps(device.staticIdentity.privateKey[:], msg.Ct1[:])

	KDF2(&chainKey, &key, C2[:], shk1)
	//C3
	aead, _ := chacha20poly1305.New(key[:])
	_, err = aead.Open(hpeerPK[:0], ZeroNonce[:], msg.Static[:], hash[:])
	if err != nil {
		return nil
	}
	mixHash(&hash, &hash, msg.Static[:])
	//H4

	// lookup peer

	peer := device.LookupPeer(hpeerPK)
	if peer == nil {
		return nil
	}

	handshake := &peer.handshake

	// verify identity

	var timestamp tai64n.Timestamp

	handshake.mutex.RLock()

	KDF2(&chainKey, &key, C2[:], handshake.presharedKey[:])
	mixKey(&chainKey, &chainKey, handshake.presharedKey[:])
	//C4
	aead, _ = chacha20poly1305.New(key[:])
	_, err = aead.Open(timestamp[:0], ZeroNonce[:], msg.Timestamp[:], hash[:])
	if err != nil {
		handshake.mutex.RUnlock()
		return nil
	}
	mixHash(&hash, &hash, msg.Timestamp[:])
	//H5

	// protect against replay & flood

	replay := !timestamp.After(handshake.lastTimestamp)
	flood := time.Since(handshake.lastInitiationConsumption) <= HandshakeInitationRate
	handshake.mutex.RUnlock()
	if replay {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake replay @ %v", peer, timestamp)
		return nil
	}
	if flood {
		device.log.Verbosef("%v - ConsumeMessageInitiation: handshake flood", peer)
		return nil
	}

	//mixKey(&chainKey, &chainKey, shk1)

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash         //H5
	handshake.chainKey = chainKey //C4
	handshake.remoteIndex = msg.Sender
	handshake.remoteEphemeral = msg.Ephemeral
	if timestamp.After(handshake.lastTimestamp) {
		handshake.lastTimestamp = timestamp
	}
	now := time.Now()
	if now.After(handshake.lastInitiationConsumption) {
		handshake.lastInitiationConsumption = now
	}
	handshake.state = handshakeInitiationConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return peer
}

func (device *Device) CreateMessageResponse(peer *Peer) (*MessageResponse, error) {
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	if handshake.state != handshakeInitiationConsumed {
		return nil, errors.New("handshake initiation must be consumed first")
	}


	// assign index

	var err error
	device.indexTable.Delete(handshake.localIndex)
	handshake.localIndex, err = device.indexTable.NewIndexForHandshake(peer, handshake)
	if err != nil {
		return nil, err
	}

	var msg MessageResponse
	msg.Type = MessageResponseType
	msg.Sender = handshake.localIndex
	msg.Receiver = handshake.remoteIndex

	var rr [4]byte
	rand.Read(rr[:])
	encSeed := sha3.Sum256(append(device.staticIdentity.sigma, rr[:]...))
	ct2, shk2 := cpaKyber.CPAEncaps(handshake.remoteEphemeral[:])
	//c4 and h5 in handshake
	handshake.mixKey(ct2) //c6
	copy(msg.Ct2[:], ct2[:])
	handshake.mixKey(shk2) //c7
	handshake.mixHash(ct2) //H6

	ct3, shk3 := ccaKyber.Encaps(handshake.remoteStatic[:], encSeed[:])
	fmt.Printf("Create: shk3 %+v\n", shk3)
	copy(msg.Ct3[:], ct3[:])
	handshake.mixKey(shk3) //c8


	// add preshared key

	var tau [blake2s.Size]byte //KDF2(c8, psk)
	var key [chacha20poly1305.KeySize]byte

	KDF3(
		&handshake.chainKey, //c9
		&tau,                //KDF2
		&key,                //k9
		handshake.chainKey[:],
		handshake.presharedKey[:],
	)

	handshake.mixHash(tau[:]) //h9

	aead, _ := chacha20poly1305.New(key[:])
	aead.Seal(msg.Empty[:0], ZeroNonce[:], nil, handshake.hash[:])
	handshake.mixHash(msg.Empty[:]) //H10

	handshake.state = handshakeResponseCreated

	return &msg, nil
}

func (device *Device) ConsumeMessageResponse(msg *MessageResponse) *Peer {
	if msg.Type != MessageResponseType {
		return nil
	}

	// lookup handshake by receiver

	lookup := device.indexTable.Lookup(msg.Receiver)
	handshake := lookup.handshake
	if handshake == nil {
		return nil
	}

	var (
		hash     [blake2s.Size]byte
		chainKey [blake2s.Size]byte
	)

	ok := func() bool {

		// lock handshake state

		handshake.mutex.RLock()
		defer handshake.mutex.RUnlock()

		if handshake.state != handshakeInitiationCreated {
			return false
		}

		copy(chainKey[:], handshake.chainKey[:])
		copy(hash[:], handshake.hash[:])


		// lock private key for reading

		device.staticIdentity.RLock()
		defer device.staticIdentity.RUnlock()

		//C4 and H5 in handshake
		shk2 := cpaKyber.CPADecaps(handshake.localEphemeral[:], msg.Ct2[:])

		mixKey(&chainKey, &chainKey, msg.Ct2[:]) //c6
		mixKey(&chainKey, &chainKey, shk2) //c7
		mixHash(&hash, &hash, msg.Ct2[:]) //H6

		shk3 := ccaKyber.Decaps(device.staticIdentity.privateKey[:], msg.Ct3[:])
		fmt.Printf("Response: shk3 %+v\n", shk3)
		mixKey(&chainKey, &chainKey, shk3) //c8
		// add preshared key (psk)

		var tau [blake2s.Size]byte
		var key [chacha20poly1305.KeySize]byte

		KDF3(
			&chainKey, //c9
			&tau,      //KDF2(c8, psk)
			&key,
			chainKey[:],
			handshake.presharedKey[:],
		)

		mixHash(&hash, &hash, tau[:]) //H9

		// authenticate transcript

		aead, _ := chacha20poly1305.New(key[:])
		_, err := aead.Open(nil, ZeroNonce[:], msg.Empty[:], hash[:])
		if err != nil {
			return false
		}

		mixHash(&hash, &hash, msg.Empty[:]) //H10
		return true
	}()

	if !ok {
		return nil
	}

	// update handshake state

	handshake.mutex.Lock()

	handshake.hash = hash         //must be H10
	handshake.chainKey = chainKey //must be C9
	handshake.remoteIndex = msg.Sender
	handshake.state = handshakeResponseConsumed

	handshake.mutex.Unlock()

	setZero(hash[:])
	setZero(chainKey[:])

	return lookup.peer
}

/* Derives a new keypair from the current handshake state
 *
 */
func (peer *Peer) BeginSymmetricSession() error {
	device := peer.device
	handshake := &peer.handshake
	handshake.mutex.Lock()
	defer handshake.mutex.Unlock()

	// derive keys

	var isInitiator bool
	var sendKey [chacha20poly1305.KeySize]byte
	var recvKey [chacha20poly1305.KeySize]byte

	if handshake.state == handshakeResponseConsumed {
		KDF2(
			&sendKey,
			&recvKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = true
	} else if handshake.state == handshakeResponseCreated {
		KDF2(
			&recvKey,
			&sendKey,
			handshake.chainKey[:],
			nil,
		)
		isInitiator = false
	} else {
		return fmt.Errorf("invalid state for keypair derivation: %v", handshake.state)
	}

	// zero handshake

	setZero(handshake.chainKey[:])
	setZero(handshake.hash[:]) // Doesn't necessarily need to be zeroed. Could be used for something interesting down the line.
	setZero(handshake.localEphemeral[:])
	peer.handshake.state = handshakeZeroed

	// create AEAD instances

	keypair := new(Keypair)
	keypair.send, _ = chacha20poly1305.New(sendKey[:])
	keypair.receive, _ = chacha20poly1305.New(recvKey[:])

	setZero(sendKey[:])
	setZero(recvKey[:])

	keypair.created = time.Now()
	keypair.replayFilter.Reset()
	keypair.isInitiator = isInitiator
	keypair.localIndex = peer.handshake.localIndex
	keypair.remoteIndex = peer.handshake.remoteIndex

	// remap index

	device.indexTable.SwapIndexForKeypair(handshake.localIndex, keypair)
	handshake.localIndex = 0

	// rotate key pairs

	keypairs := &peer.keypairs
	keypairs.Lock()
	defer keypairs.Unlock()

	previous := keypairs.previous
	next := keypairs.loadNext()
	current := keypairs.current

	if isInitiator {
		if next != nil {
			keypairs.storeNext(nil)
			keypairs.previous = next
			device.DeleteKeypair(current)
		} else {
			keypairs.previous = current
		}
		device.DeleteKeypair(previous)
		keypairs.current = keypair
	} else {
		keypairs.storeNext(keypair)
		device.DeleteKeypair(next)
		keypairs.previous = nil
		device.DeleteKeypair(previous)
	}

	return nil
}

func (peer *Peer) ReceivedWithKeypair(receivedKeypair *Keypair) bool {
	keypairs := &peer.keypairs

	if keypairs.loadNext() != receivedKeypair {
		return false
	}
	keypairs.Lock()
	defer keypairs.Unlock()
	if keypairs.loadNext() != receivedKeypair {
		return false
	}
	old := keypairs.previous
	keypairs.previous = keypairs.current
	peer.device.DeleteKeypair(old)
	keypairs.current = keypairs.loadNext()
	keypairs.storeNext(nil)
	return true
}
