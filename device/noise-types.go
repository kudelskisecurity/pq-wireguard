/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/subtle"
	"encoding/hex"
)

type (
	NoiseNonce uint64 // padded to 12-bytes

	CPAKyberPK [sizeCPAKyberPK]byte
	CPAKyberSK [sizeCPAKyberSK]byte

	CCAKyberPK [sizeCCAKyberPK]byte
	CCAKyberSK [sizeCCAKyberSK]byte
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	copy(dst, slice)
	return nil
}

func (key CCAKyberSK) IsZero() bool {
	var zero CCAKyberSK
	return key.Equals(zero)
}

func (key CCAKyberSK) Equals(tar CCAKyberSK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func KeyToHex(key []byte) string {
	return hex.EncodeToString(key[:])
}

func FromHex(dst []byte, src string) error {
	return loadExactHex(dst, src)
}

func (key CCAKyberPK) IsZero() bool {
	var zero CCAKyberPK
	return key.Equals(zero)
}

func (key CCAKyberPK) Equals(tar CCAKyberPK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}
