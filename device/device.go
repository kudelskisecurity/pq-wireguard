/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kudelskisecurity/wireguard/conn"
	"github.com/kudelskisecurity/wireguard/ratelimiter"
	"github.com/kudelskisecurity/wireguard/rwcancel"
	"github.com/kudelskisecurity/wireguard/tun"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/sha3"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type Device struct {
	isUp     AtomicBool // device is (going) up
	isClosed AtomicBool // device is closed? (acting as guard)
	log      *Logger
	ipcSetMu sync.Mutex // serializes UAPI set operations

	// synchronized resources (locks acquired in order)

	state struct {
		stopping sync.WaitGroup
		sync.Mutex
		changing AtomicBool
		current  bool
	}

	net struct {
		stopping sync.WaitGroup
		sync.RWMutex
		bind          conn.Bind // bind interface
		netlinkCancel *rwcancel.RWCancel
		port          uint16 // listening port
		fwmark        uint32 // mark value (0 = disabled)
	}

	staticIdentity struct {
		sync.RWMutex
		privateKey CCAKyberSK
		publicKey  CCAKyberPK
		sigma      []byte //long term secret
	}

	peers struct {
		empty        AtomicBool                   // empty reports whether len(keyMap) == 0
		sync.RWMutex                              // protects keyMap
		keyMap       map[[blake2s.Size]byte]*Peer //map h(pk) to peer
	}

	// unprotected / "self-synchronising resources"

	allowedips    AllowedIPs
	indexTable    IndexTable
	cookieChecker CookieChecker

	rate struct {
		underLoadUntil atomic.Value
		limiter        ratelimiter.Ratelimiter
	}

	pool struct {
		messageBufferPool        *sync.Pool
		messageBufferReuseChan   chan *[MaxMessageSize]byte
		inboundElementPool       *sync.Pool
		inboundElementReuseChan  chan *QueueInboundElement
		outboundElementPool      *sync.Pool
		outboundElementReuseChan chan *QueueOutboundElement
	}

	queue struct {
		encryption *encryptionQueue
		decryption *decryptionQueue
		handshake  chan QueueHandshakeElement
	}

	signals struct {
		stop chan struct{}
	}

	tun struct {
		device tun.Device
		mtu    int32
	}
}

// An encryptionQueue is a channel of QueueOutboundElements awaiting encryption.
// An encryptionQueue is ref-counted using its wg field.
// An encryptionQueue created with newEncryptionQueue has one reference.
// Every additional writer must call wg.Add(1).
// Every completed writer must call wg.Done().
// When no further writers will be added,
// call wg.Done to remove the initial reference.
// When the refcount hits 0, the queue's channel is closed.
type encryptionQueue struct {
	c  chan *QueueOutboundElement
	wg sync.WaitGroup
}

func newEncryptionQueue() *encryptionQueue {
	q := &encryptionQueue{
		c: make(chan *QueueOutboundElement, QueueOutboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

// A decryptionQueue is similar to an encryptionQueue; see those docs.
type decryptionQueue struct {
	c  chan *QueueInboundElement
	wg sync.WaitGroup
}

func newDecryptionQueue() *decryptionQueue {
	q := &decryptionQueue{
		c: make(chan *QueueInboundElement, QueueInboundSize),
	}
	q.wg.Add(1)
	go func() {
		q.wg.Wait()
		close(q.c)
	}()
	return q
}

/* Converts the peer into a "zombie", which remains in the peer map,
 * but processes no packets and does not exists in the routing table.
 *
 * Must hold device.peers.Mutex
 */
func unsafeRemovePeer(device *Device, peer *Peer, hk [blake2s.Size]byte) {

	// stop routing and processing of packets

	device.allowedips.RemoveByPeer(peer)
	peer.Stop()

	// remove from peer map
	delete(device.peers.keyMap, hk)
	device.peers.empty.Set(len(device.peers.keyMap) == 0)
}

func deviceUpdateState(device *Device) {

	// check if state already being updated (guard)

	if device.state.changing.Swap(true) {
		return
	}

	// compare to current state of device

	device.state.Lock()

	newIsUp := device.isUp.Get()

	if newIsUp == device.state.current {
		device.state.changing.Set(false)
		device.state.Unlock()
		return
	}

	// change state of device

	switch newIsUp {
	case true:
		if err := device.BindUpdate(); err != nil {
			device.log.Errorf("Unable to update bind: %v", err)
			device.isUp.Set(false)
			break
		}
		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Start()
			if atomic.LoadUint32(&peer.persistentKeepaliveInterval) > 0 {
				peer.SendKeepalive()
			}
		}
		device.peers.RUnlock()

	case false:
		device.BindClose()
		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Stop()
		}
		device.peers.RUnlock()
	}

	// update state variables

	device.state.current = newIsUp
	device.state.changing.Set(false)
	device.state.Unlock()

	// check for state change in the mean time

	deviceUpdateState(device)
}

func (device *Device) Up() {

	// closed device cannot be brought up

	if device.isClosed.Get() {
		return
	}

	device.isUp.Set(true)
	deviceUpdateState(device)
}

func (device *Device) Down() {
	device.isUp.Set(false)
	deviceUpdateState(device)
}

func (device *Device) IsUnderLoad() bool {

	// check if currently under load

	now := time.Now()
	underLoad := len(device.queue.handshake) >= UnderLoadQueueSize
	if underLoad {
		device.rate.underLoadUntil.Store(now.Add(UnderLoadAfterTime))
		return true
	}

	// check if recently under load

	until := device.rate.underLoadUntil.Load().(time.Time)
	return until.After(now)
}

//Set the KEM keys
func (device *Device) SetPrivateKey(sk CCAKyberSK) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	if bytes.Compare(sk[:], device.staticIdentity.privateKey[:]) == 0 {
		//already up to date (or both all 0 !! TODO here)
		return nil
	}

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// update key material

	device.staticIdentity.privateKey = sk
	sig := sha3.Sum256(sk[:])
	device.staticIdentity.sigma = sig[:]

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

//Set the KEM keys
func (device *Device) SetPublicKey(pk CCAKyberPK) error {
	// lock required resources

	device.staticIdentity.Lock()
	defer device.staticIdentity.Unlock()

	device.peers.Lock()
	defer device.peers.Unlock()

	lockedPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		peer.handshake.mutex.RLock()
		lockedPeers = append(lockedPeers, peer)
	}

	// remove peers with matching public keys

	for hk, peer := range device.peers.keyMap {
		if bytes.Compare(peer.handshake.remoteStatic[:], pk[:]) == 0 {
			unsafeRemovePeer(device, peer, hk)
		}
	}

	// update key material
	device.staticIdentity.publicKey = pk
	device.cookieChecker.Init(pk)

	// do static-static DH pre-computations

	expiredPeers := make([]*Peer, 0, len(device.peers.keyMap))
	for _, peer := range device.peers.keyMap {
		handshake := &peer.handshake
		var h CCAKyberPK
		for i, b := range device.staticIdentity.publicKey {
			h[i] = b | handshake.remoteStatic[i]
		}
		hpks := blake2s.Sum256(h[:])
		copy(handshake.presharedKey[:], hpks[:])
		//var ss NoiseSymmetricKey
		//handshake.precomputedStaticStatic = ss //device.staticIdentity.privateKey.sharedSecret(handshake.remoteStatic) //here
		expiredPeers = append(expiredPeers, peer)
	}

	for _, peer := range lockedPeers {
		peer.handshake.mutex.RUnlock()
	}
	for _, peer := range expiredPeers {
		peer.ExpireCurrentKeypairs()
	}

	return nil
}

func NewDevice(tunDevice tun.Device, logger *Logger) *Device {
	device := new(Device)
	device.log = logger
	device.tun.device = tunDevice
	mtu, err := device.tun.device.MTU()
	if err != nil {
		device.log.Errorf("Trouble determining MTU, assuming default: %v", err)
		mtu = DefaultMTU
	}
	device.tun.mtu = int32(mtu)

	device.peers.keyMap = make(map[[blake2s.Size]byte]*Peer)

	device.rate.limiter.Init()
	device.rate.underLoadUntil.Store(time.Time{})

	device.indexTable.Init()
	device.allowedips.Reset()

	device.PopulatePools()

	// create queues

	device.queue.handshake = make(chan QueueHandshakeElement, QueueHandshakeSize)
	device.queue.encryption = newEncryptionQueue()
	device.queue.decryption = newDecryptionQueue()

	// prepare signals

	device.signals.stop = make(chan struct{})

	// prepare net

	device.net.port = 0
	device.net.bind = nil

	// start workers

	cpus := runtime.NumCPU()
	device.state.stopping.Wait()
	for i := 0; i < cpus; i++ {
		device.state.stopping.Add(2) // decryption and handshake
		go device.RoutineEncryption()
		go device.RoutineDecryption()
		go device.RoutineHandshake()
	}

	device.state.stopping.Add(2)
	go device.RoutineReadFromTUN()
	go device.RoutineTUNEventReader()

	return device
}

func (device *Device) LookupPeer(hpk [blake2s.Size]byte) *Peer {
	device.peers.RLock()
	defer device.peers.RUnlock()
	return device.peers.keyMap[hpk]
}

func (device *Device) RemovePeer(hk [blake2s.Size]byte) {
	device.peers.Lock()
	defer device.peers.Unlock()
	// stop peer and remove from routing
	peer, ok := device.peers.keyMap[hk]
	if ok {
		unsafeRemovePeer(device, peer, hk)
	}
}

func (device *Device) RemoveAllPeers() {
	device.peers.Lock()
	defer device.peers.Unlock()

	for hk, peer := range device.peers.keyMap {
		unsafeRemovePeer(device, peer, hk)
	}

	device.peers.keyMap = make(map[[blake2s.Size]byte]*Peer)
}

func (device *Device) FlushPacketQueues() {
	for {
		select {
		case elem := <-device.queue.handshake:
			device.PutMessageBuffer(elem.buffer)
		default:
			return
		}
	}

}

func (device *Device) Close() {
	if device.isClosed.Swap(true) {
		return
	}

	device.log.Verbosef("Device closing")
	device.state.changing.Set(true)
	device.state.Lock()
	defer device.state.Unlock()

	device.tun.device.Close()
	device.BindClose()

	device.isUp.Set(false)

	// We kept a reference to the encryption and decryption queues,
	// in case we started any new peers that might write to them.
	// No new peers are coming; we are done with these queues.
	device.queue.encryption.wg.Done()
	device.queue.decryption.wg.Done()
	close(device.signals.stop)
	device.state.stopping.Wait()

	device.RemoveAllPeers()

	device.FlushPacketQueues()

	device.rate.limiter.Close()

	device.state.changing.Set(false)
	device.log.Verbosef("Interface closed")
}

func (device *Device) Wait() chan struct{} {
	return device.signals.stop
}

func (device *Device) SendKeepalivesToPeersWithCurrentKeypair() {
	if device.isClosed.Get() {
		return
	}

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.keypairs.RLock()
		sendKeepalive := peer.keypairs.current != nil && !peer.keypairs.current.created.Add(RejectAfterTime).Before(time.Now())
		peer.keypairs.RUnlock()
		if sendKeepalive {
			peer.SendKeepalive()
		}
	}
	device.peers.RUnlock()
}

func unsafeCloseBind(device *Device) error {
	var err error
	netc := &device.net
	if netc.netlinkCancel != nil {
		netc.netlinkCancel.Cancel()
	}
	if netc.bind != nil {
		err = netc.bind.Close()
		netc.bind = nil
	}
	netc.stopping.Wait()
	return err
}

func (device *Device) Bind() conn.Bind {
	device.net.Lock()
	defer device.net.Unlock()
	return device.net.bind
}

func (device *Device) BindSetMark(mark uint32) error {

	device.net.Lock()
	defer device.net.Unlock()

	// check if modified

	if device.net.fwmark == mark {
		return nil
	}

	// update fwmark on existing bind

	device.net.fwmark = mark
	if device.isUp.Get() && device.net.bind != nil {
		if err := device.net.bind.SetMark(mark); err != nil {
			return err
		}
	}

	// clear cached source addresses

	device.peers.RLock()
	for _, peer := range device.peers.keyMap {
		peer.Lock()
		defer peer.Unlock()
		if peer.endpoint != nil {
			peer.endpoint.ClearSrc()
		}
	}
	device.peers.RUnlock()

	return nil
}

func (device *Device) BindUpdate() error {

	device.net.Lock()
	defer device.net.Unlock()

	// close existing sockets

	if err := unsafeCloseBind(device); err != nil {
		return err
	}

	// open new sockets

	if device.isUp.Get() {

		// bind to new port

		var err error
		netc := &device.net
		netc.bind, netc.port, err = conn.CreateBind(netc.port)
		if err != nil {
			netc.bind = nil
			netc.port = 0
			return err
		}
		netc.netlinkCancel, err = device.startRouteListener(netc.bind)
		if err != nil {
			netc.bind.Close()
			netc.bind = nil
			netc.port = 0
			return err
		}

		// set fwmark

		if netc.fwmark != 0 {
			err = netc.bind.SetMark(netc.fwmark)
			if err != nil {
				return err
			}
		}

		// clear cached source addresses

		device.peers.RLock()
		for _, peer := range device.peers.keyMap {
			peer.Lock()
			defer peer.Unlock()
			if peer.endpoint != nil {
				peer.endpoint.ClearSrc()
			}
		}
		device.peers.RUnlock()

		// start receiving routines

		device.net.stopping.Add(2)
		device.queue.decryption.wg.Add(2) // each RoutineReceiveIncoming goroutine writes to device.queue.decryption
		go device.RoutineReceiveIncoming(ipv4.Version, netc.bind)
		go device.RoutineReceiveIncoming(ipv6.Version, netc.bind)

		device.log.Verbosef("UDP bind has been updated")
	}

	return nil
}

func (device *Device) BindClose() error {
	device.net.Lock()
	err := unsafeCloseBind(device)
	device.net.Unlock()
	return err
}

func (device *Device) PrintDevice() {
	device.log.Verbosef("Device info:\nSK: %x\nPK: %x\npeer: %+v\n", device.staticIdentity.privateKey, device.staticIdentity.publicKey, device.peers.keyMap)
}

func GenerateDeviceKeys() ([]byte, []byte){
	return ccaKyber.KeyGen(nil)
}
