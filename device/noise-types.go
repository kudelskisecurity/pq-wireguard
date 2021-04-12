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

	KyberPKEPK [kyber.Kyber768SizePK]byte
	KyberPKESK [kyber.Kyber768SizePKESK]byte //kyber.Kyber768SizePKESK undefined ??

	KyberKEMPK [kyber.Kyber768SizePK]byte
	KyberKEMSK [kyber.Kyber768SizeSK]byte
)

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	copy(dst, slice)
	return nil
}

func (key KyberKEMSK) IsZero() bool {
	var zero KyberKEMSK
	return key.Equals(zero)
}

func (key KyberKEMSK) Equals(tar KyberKEMSK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func KeyToHex(key []byte) string {
	return hex.EncodeToString(key[:])
}

func FromHex(dst []byte, src string) error {
	return loadExactHex(dst, src)
}

func (key KyberKEMPK) IsZero() bool {
	var zero KyberKEMPK
	return key.Equals(zero)
}

func (key KyberKEMPK) Equals(tar KyberKEMPK) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}
