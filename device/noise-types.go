/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"

	kyber "gitlab.kudelski.com/ks-fun/go-pqs/crystals-kyber"
)

type (
	NoiseNonce uint64 // padded to 12-bytes

	KyberPK [kyber.Kyber512SizePK]byte
	KyberSK [kyber.Kyber512SizePKESK]byte //kyber.Kyber512SizePKESK undefined ??

	RainbowPK [RainbowPKSize]byte
	RainbowSK [RainbowSKSize]byte
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	copy(dst, slice)
	return nil
}

func (key RainbowSK) IsZero() bool {
	var zero RainbowSK
	return key.Equals(zero)
}

func (key RainbowSK) Equals(tar RainbowSK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func KeyToHex(key []byte) string {
	return hex.EncodeToString(key[:])
}

func FromHex(dst []byte, src string) error {
	return loadExactHex(dst, src)
}

func (key RainbowPK) IsZero() bool {
	var zero RainbowPK
	return key.Equals(zero)
}

func (key RainbowPK) Equals(tar RainbowPK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}
