/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package attestation

import (
	"crypto"
	"hash"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

// This file is copy of PR https://github.com/golang/crypto/pull/50/files which
// ass Sign method to openpgp.
// Along with Sing, we copy the private methods used in openpgp.Sign and renamed
// it to <methodName>Copy

// Copy of openpgp.Sign
func Sign(ciphertext io.Writer, signed *openpgp.Entity, hints *openpgp.FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	if signed == nil {
		return nil, errors.InvalidArgumentError("no signer provided")
	}

	// These are the possible hash functions that we'll use for the signature.
	candidateHashes := []uint8{
		hashToHashIdCopy(crypto.SHA256),
		hashToHashIdCopy(crypto.SHA512),
		hashToHashIdCopy(crypto.SHA1),
		hashToHashIdCopy(crypto.RIPEMD160),
	}
	defaultHashes := candidateHashes[len(candidateHashes)-1:]
	preferredHashes := primaryIdentityCopy(signed).SelfSignature.PreferredHash
	if len(preferredHashes) == 0 {
		preferredHashes = defaultHashes
	}
	candidateHashes = intersectPreferencesCopy(candidateHashes, preferredHashes)
	return writeAndSign(noOpCloserCopy{ciphertext}, candidateHashes, signed, hints, config)
}

// intersectPreferencesCopy is copy of openpgp.intersectPreferences
func intersectPreferencesCopy(a []uint8, b []uint8) (intersection []uint8) {
	var j int
	for _, v := range a {
		for _, v2 := range b {
			if v == v2 {
				a[j] = v
				j++
				break
			}
		}
	}

	return a[:j]
}

// writeAndSign writes the data as a payload package and, optionally, signs
// it. hints contains optional information, that is also encrypted,
// that aids the recipients in processing the message. The resulting
// WriteCloser must be closed after the contents of the file have been
// written. If config is nil, sensible defaults will be used.
func writeAndSign(payload io.WriteCloser, candidateHashes []uint8, signed *openpgp.Entity, hints *openpgp.FileHints, config *packet.Config) (plaintext io.WriteCloser, err error) {
	var signer *packet.PrivateKey
	if signed != nil {
		signKey, ok := signingKeyCopy(signed, config.Now())
		if !ok {
			return nil, errors.InvalidArgumentError("no valid signing keys")
		}
		signer = signKey.PrivateKey
		if signer == nil {
			return nil, errors.InvalidArgumentError("no private key in signing key")
		}
		if signer.Encrypted {
			return nil, errors.InvalidArgumentError("signing key must be decrypted")
		}
	}

	var hash crypto.Hash
	for _, hashId := range candidateHashes {
		if h, ok := s2k.HashIdToHash(hashId); ok && h.Available() {
			hash = h
			break
		}
	}

	// If the hash specified by config is a candidate, we'll use that.
	if configuredHash := config.Hash(); configuredHash.Available() {
		for _, hashId := range candidateHashes {
			if h, ok := s2k.HashIdToHash(hashId); ok && h == configuredHash {
				hash = h
				break
			}
		}
	}

	if hash == 0 {
		hashId := candidateHashes[0]
		name, ok := s2k.HashIdToString(hashId)
		if !ok {
			name = "#" + strconv.Itoa(int(hashId))
		}
		return nil, errors.InvalidArgumentError("cannot encrypt because no candidate hash functions are compiled in. (Wanted " + name + " in this case.)")
	}

	if signer != nil {
		ops := &packet.OnePassSignature{
			SigType:    packet.SigTypeBinary,
			Hash:       hash,
			PubKeyAlgo: signer.PubKeyAlgo,
			KeyId:      signer.KeyId,
			IsLast:     true,
		}
		if err := ops.Serialize(payload); err != nil {
			return nil, err
		}
	}

	if hints == nil {
		hints = &openpgp.FileHints{}
	}

	w := payload
	if signer != nil {
		// If we need to write a signature packet after the literal
		// data then we need to stop literalData from closing
		// encryptedData.
		w = noOpCloserCopy{w}

	}
	var epochSeconds uint32
	if !hints.ModTime.IsZero() {
		epochSeconds = uint32(hints.ModTime.Unix())
	}
	literalData, err := packet.SerializeLiteral(w, hints.IsBinary, hints.FileName, epochSeconds)
	if err != nil {
		return nil, err
	}

	if signer != nil {
		return signatureWriterCopy{payload, literalData, hash, hash.New(), signer, config}, nil
	}
	return literalData, nil
}

// hashToHashIdCopy is Copy of openpgp.hashToHashId
func hashToHashIdCopy(h crypto.Hash) uint8 {
	v, ok := s2k.HashToHashId(h)
	if !ok {
		panic("tried to convert unknown hash")
	}
	return v
}

// signatureWriterCopy is Copy of openpgp.signatureWriter and its methods.
type signatureWriterCopy struct {
	encryptedData io.WriteCloser
	literalData   io.WriteCloser
	hashType      crypto.Hash
	h             hash.Hash
	signer        *packet.PrivateKey
	config        *packet.Config
}

func (s signatureWriterCopy) Write(data []byte) (int, error) {
	s.h.Write(data)
	return s.literalData.Write(data)
}

func (s signatureWriterCopy) Close() error {
	sig := &packet.Signature{
		SigType:      packet.SigTypeBinary,
		PubKeyAlgo:   s.signer.PubKeyAlgo,
		Hash:         s.hashType,
		CreationTime: s.config.Now(),
		IssuerKeyId:  &s.signer.KeyId,
	}

	if err := sig.Sign(s.h, s.signer, s.config); err != nil {
		return err
	}
	if err := s.literalData.Close(); err != nil {
		return err
	}
	if err := sig.Serialize(s.encryptedData); err != nil {
		return err
	}
	return s.encryptedData.Close()
}

// noOpCloserCopy is copy of openpgp.noOpCloser
type noOpCloserCopy struct {
	w io.Writer
}

func (c noOpCloserCopy) Write(data []byte) (n int, err error) {
	return c.w.Write(data)
}

func (c noOpCloserCopy) Close() error {
	return nil
}

func signingKeyCopy(e *openpgp.Entity, now time.Time) (openpgp.Key, bool) {
	candidateSubkey := -1

	for i, subkey := range e.Subkeys {
		if subkey.Sig.FlagsValid &&
			subkey.Sig.FlagSign &&
			subkey.PublicKey.PubKeyAlgo.CanSign() &&
			!subkey.Sig.KeyExpired(now) {
			candidateSubkey = i
			break
		}
	}

	if candidateSubkey != -1 {
		subkey := e.Subkeys[candidateSubkey]
		return openpgp.Key{e, subkey.PublicKey, subkey.PrivateKey, subkey.Sig}, true
	}

	// If we have no candidate subkey then we assume that it's ok to sign
	// with the primary key.
	i := primaryIdentityCopy(e)
	if !i.SelfSignature.FlagsValid || i.SelfSignature.FlagSign &&
		!i.SelfSignature.KeyExpired(now) {
		return openpgp.Key{e, e.PrimaryKey, e.PrivateKey, i.SelfSignature}, true
	}

	return openpgp.Key{}, false
}

// primaryIdentityCopy is a copy of openpgp.PrimaryIdentity.
func primaryIdentityCopy(e *openpgp.Entity) *openpgp.Identity {
	var firstIdentity *openpgp.Identity
	for _, ident := range e.Identities {
		if firstIdentity == nil {
			firstIdentity = ident
		}
		if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
			return ident
		}
	}
	return firstIdentity
}
