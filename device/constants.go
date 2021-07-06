/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"

	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
	oqs "github.com/open-quantum-safe/liboqs-go/oqs"
)

/* Specification constants */

const (
	RekeyAfterMessages      = (1 << 60)
	RejectAfterMessages     = (1 << 64) - (1 << 13) - 1
	RekeyAfterTime          = time.Second * 120
	RekeyAttemptTime        = time.Second * 90
	RekeyTimeout            = time.Second * 5
	MaxTimerHandshakes      = 90 / 5 /* RekeyAttemptTime / RekeyTimeout */
	RekeyTimeoutJitterMaxMs = 334
	RejectAfterTime         = time.Second * 180
	KeepaliveTimeout        = time.Second * 10
	CookieRefreshTime       = time.Second * 120
	HandshakeInitationRate  = time.Second / 50
	PaddingMultiple         = 16
)

const (
	MinMessageSize = MessageKeepaliveSize                  // minimum size of transport message (keepalive)
	MaxMessageSize = MaxSegmentSize                        // maximum size of transport message
	MaxContentSize = MaxSegmentSize - MessageTransportSize // maximum size of transport message content
)

/* Implementation constants */

const (
	UnderLoadQueueSize = QueueHandshakeSize / 8
	UnderLoadAfterTime = time.Second // how long does the device remain under load after detected
	MaxPeers           = 1 << 16     // maximum number of configured peers
)

//The DSA instance to be used
var r = "Rainbow-I-Classic" //Classic//Compressed
var verifier = oqs.Signature{}

const (
	//	SignatureSize = 164    //66
	sizeRainbowSig = 66
	//RainbowSKSize = 626048 //103648 //64
	sizeRainbowSK = 103648 //64
	//RainbowPKSize = 882080 //161600 //60192
	sizeRainbowPK = 161600 //60192
)

//The CPA secure KEM instance to be used
var cpaKyber = kyber.NewTweakedKyber512()

const (
	sizeCPAKyberPK = kyber.Kyber512SizePK
	sizeCPAKyberC  = kyber.KyberTweaked512SizeC
	sizeCPAKyberSK = kyber.Kyber512SizePKESK
)
