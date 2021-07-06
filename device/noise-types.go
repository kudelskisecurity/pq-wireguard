/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	b64 "encoding/base64"
)

type (
	NoiseNonce uint64 // padded to 12-bytes

	RainbowPK [sizeRainbowPK]byte
	RainbowSK [sizeRainbowSK]byte

	CPAKyberPK [sizeCPAKyberPK]byte
	CPAKyberSK [sizeCPAKyberSK]byte
)

func (key RainbowSK) IsZero() bool {
	var zero RainbowSK
	return key.Equals(zero)
}

func (key RainbowSK) Equals(tar RainbowSK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func ToB64(key []byte) string {
	return b64.StdEncoding.EncodeToString(key)
}

func FromB64(dst []byte, src string) error {
	srcDec, err := b64.StdEncoding.DecodeString(src)
	copy(dst, srcDec)
	return err
}

func (key RainbowPK) IsZero() bool {
	var zero RainbowPK
	return key.Equals(zero)
}

func (key RainbowPK) Equals(tar RainbowPK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}
