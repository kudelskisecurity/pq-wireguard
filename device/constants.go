/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"time"

	kyber "github.com/kudelskisecurity/crystals-go/crystals-kyber"
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

//The CCA secure KEM instance to be used
var ccaKyber = kyber.NewKyber768()

const (
	sizeCCAKyberPK = kyber.Kyber768SizePK
	sizeCCAKyberSK = kyber.Kyber768SizeSK
	sizeCCAKyberC  = kyber.Kyber768SizeC
)

//The CPA secure KEM instance to be used
var cpaKyber = kyber.NewKyber768()

const (
	sizeCPAKyberPK = kyber.Kyber768SizePK
	sizeCPAKyberC  = kyber.Kyber768SizeC
	sizeCPAKyberSK = kyber.Kyber768SizeSK
)
