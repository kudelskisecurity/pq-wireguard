/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestNoiseHanshakeSizes(t *testing.T) {
	fmt.Printf("Message init size %v, message response size %+v\n", MessageInitiationSize, MessageResponseSize)
}

func BenchmarkHandshakeServer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dev1 := randDevice()
		dev2 := randDevice()
		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)
		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		msg1, _ := dev1.CreateMessageInitiation(peer2)
		packet := make([]byte, 0, 256)
		writer := bytes.NewBuffer(packet)
		binary.Write(writer, binary.LittleEndian, msg1)

		b.StartTimer()
		dev2.ConsumeMessageInitiation(msg1)
		dev2.CreateMessageResponse(peer1)
		b.StopTimer()

		dev1.Close()
		dev2.Close()
	}
}

func BenchmarkHandshakeClient(b *testing.B) {
	for i := 0; i < b.N; i++ {
		dev1 := randDevice()
		dev2 := randDevice()
		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)
		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		b.StartTimer()
		msg1, _ := dev1.CreateMessageInitiation(peer2)
		packet := make([]byte, 0, 256)
		writer := bytes.NewBuffer(packet)
		binary.Write(writer, binary.LittleEndian, msg1)
		b.StopTimer()

		dev2.ConsumeMessageInitiation(msg1)
		msg2, _ := dev2.CreateMessageResponse(peer1)

		b.StartTimer()
		dev1.ConsumeMessageResponse(msg2)
		b.StopTimer()

		dev1.Close()
		dev2.Close()
	}
}

func BenchmarkHandshake(b *testing.B) {
	for i := 0; i < b.N; i++ {

		//ignore errors everywhere
		dev1 := randDevice()
		dev2 := randDevice()

		peer1, _ := dev2.NewPeer(dev1.staticIdentity.publicKey)
		peer2, _ := dev1.NewPeer(dev2.staticIdentity.publicKey)

		/* simulate handshake */

		// initiation message

		msg1, _ := dev1.CreateMessageInitiation(peer2)

		packet := make([]byte, 0, 256)
		writer := bytes.NewBuffer(packet)
		binary.Write(writer, binary.LittleEndian, msg1)
		dev2.ConsumeMessageInitiation(msg1)

		// response message

		msg2, _ := dev2.CreateMessageResponse(peer1)

		dev1.ConsumeMessageResponse(msg2)

		// key pairs

		peer1.BeginSymmetricSession()

		peer2.BeginSymmetricSession()

		/** can't code test but manualy tested and ok
		assertEqual(
			t,
			peer1.keypairs.next.send,
			peer2.keypairs.Current().receive)**/

		key1 := peer1.keypairs.loadNext()
		key2 := peer2.keypairs.current

		// encrypting / decryption test

		func() {
			testMsg := []byte("wireguard test message 1")
			var out []byte
			var nonce [12]byte
			out = key1.send.Seal(out, nonce[:], testMsg, nil)
			out, _ = key2.receive.Open(out[:0], nonce[:], out, nil)
		}()

		func() {
			testMsg := []byte("wireguard test message 2")
			var out []byte
			var nonce [12]byte
			out = key2.send.Seal(out, nonce[:], testMsg, nil)
			out, _ = key1.receive.Open(out[:0], nonce[:], out, nil)
		}()
		dev1.Close()
		dev2.Close()
	}
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice()
	dev2 := randDevice()

	defer dev1.Close()
	defer dev2.Close()

	//	fmt.Printf("Dev1: %x\nDev2: %x\n", dev1.staticIdentity.publicKey[:], dev2.staticIdentity.publicKey[:])
	//	fmt.Printf("Dev1: %x\nDev2: %x\n", dev1.staticIdentity.privateKey[:], dev2.staticIdentity.privateKey[:])

	peer1, err := dev2.NewPeer(dev1.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(
		t,
		peer1.handshake.presharedKey[:],
		peer2.handshake.presharedKey[:],
	)

	if bytes.Equal(peer1.handshake.presharedKey[:], make([]byte, 32)) {
		t.Fatal("preshared nil")
	}
	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)
	peer := dev2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	fmt.Printf("The symmetric key was successfully derived.\n")

	/** can't code test but manualy tested and ok
	assertEqual(
		t,
		peer1.keypairs.next.send,
		peer2.keypairs.Current().receive)**/

	key1 := peer1.keypairs.loadNext()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("wireguard test message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard test message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	fmt.Printf("The first message was correctfully exchanged.\n")

}

func TestDeterministicNoiseHandshake(t *testing.T) {
	dev1 := deterDevice0()
	dev2 := deterDevice1()

	defer dev1.Close()
	defer dev2.Close()

	// fmt.Printf("Dev1: %v\nDev2: %v\n", dev1.staticIdentity.publicKey[:8], dev2.staticIdentity.publicKey[:8])
	// fmt.Printf("Dev1: %v\nDev2: %v\n", dev1.staticIdentity.privateKey[:8], dev2.staticIdentity.privateKey[:8])

	peer1, err := dev2.NewPeer(dev1.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}
	peer2, err := dev1.NewPeer(dev2.staticIdentity.publicKey)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(
		t,
		peer1.handshake.presharedKey[:],
		peer2.handshake.presharedKey[:],
	)

	if bytes.Equal(peer1.handshake.presharedKey[:], make([]byte, 32)) {
		t.Fatal("preshared nil")
	}
	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)
	peer := dev2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	fmt.Printf("The symmetric key was successfully derived.\n")

	/** can't code test but manualy tested and ok
	assertEqual(
		t,
		peer1.keypairs.next.send,
		peer2.keypairs.Current().receive)**/

	key1 := peer1.keypairs.loadNext()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("wireguard test message 1")
		var err error
		var out []byte
		var nonce [12]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard test message 2")
		var err error
		var out []byte
		var nonce [12]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	fmt.Printf("The first message was correctfully exchanged.\n")

}
