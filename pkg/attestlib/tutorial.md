# Attestation Library Tutorial

## Signing

The Signer generates Attestations using a private key. Before creating any Attestations, you must first create a Signer initialized with a private key. Then you can pass the Signer a payload, which the Signer signs and returns in an Attestation.

1. Create a Signer.
   
   Create a Signer by calling the appropriate `NewSigner` constructor based on the type of Attestation you wish to create. For example, if you want to create PGP Attestations, call `NewPgpSigner`.
   
   ### PGP
   For PGP, the signer is constructed by passing in an ASCII-armored PGP private key. If the private key is passphrase-encrypted, the passphrase should be passed through the `passphrase` argument. Otherwise, `passphrase` should be an empty string.
   ```
   privateKey := `-----BEGIN PGP PRIVATE KEY BLOCK-----
   ...
   `
   passphrase := "some-passphrase"
   signer, err := NewPgpSigner([]byte(privateKey), passphrase)
   ```
   
   ### Raw PKIX / JWT
   For PKIX and JWT, the signer is constructed by passing in the ASCII-armored private key and its SignatureAlgorithm (see [list of supported SignatureAlgorithms](https://github.com/grafeas/kritis/blob/master/pkg/attestlib/signature_algorithm.go#L24)), as well as the ID of the corresponding public key:
   
   #### PKIX
   ```
   privateKey := `-----BEGIN PRIVATE KEY-----
   ...
   `
   signer, err := NewPkixSigner([]byte(privateKey), "some-key-id", EcdsaP256Sha256)
   ```
   
   #### JWT
   ```
   privateKey := `-----BEGIN PRIVATE KEY-----
   ...
   `
   signer, err := NewJwtSigner([]byte(privateKey), "some-key-id", EcdsaP256Sha256)
   ```
   
   
2. Call CreateAttestation.

	Create an Attestation by calling the Signer’s `CreateAttestation` method, passing in the payload you wish to have signed as a byte array. The payload should contain the image name and digest.
    
    ```
    payload := `{
        "critical": {
            ...
    }`
    attestation, err := signer.CreateAttestation([]byte(payload))
    ```
    
   ### PGP
    For PGP, the `CreateAttestation` method creates an attached signature and stores it in the Attestation’s `Signature` field. (An attached signature contains both the signature and the signed payload). 

   ### PKIX
    For PKIX, the `CreateAttestation` method creates a signature and stores it in the Attestation’s `Signature` field. The signed payload is stored in the Attestation’s `SerializedPayload` field.
    
   ### JWT
   The `CreateAttestation` method generates a JWT consisting of three parts: a header, payload, and signature. The following fields are populated in the header:
   ```
   {
       "typ": "JWT",
       "alg": signature_algorithm,
       "kid": public_key_id,
   }
   ```

   The payload containing the image digest is stored in the payload section. The signature is stored in the signature section. The JWT is serialized and stored in the Attestation’s `Signature` field.
   
   
## Verifying

The Verifier holds a set of PublicKeys. When given an Attestation, the Verifier checks if any of its PublicKeys can verify the Attestation. To verify an Attestation, you must create a Verifier, which is initialized with a set of PublicKeys.

1. Create a slice of PublicKeys.

   Create a PublicKey by calling the appropriate `NewPublicKey` constructor based on the type of Attestation that key should verify. For example, if you have a key that verifies PGP Attestations, call `NewPgpPublicKey`.
   
   ### PGP
   A PGP PublicKey can be created by passing in the raw key material:
   ```
   publicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----
   `
   key, err := NewPgpPublicKey([]byte(publicKey))
   ```
   
   ### Raw PKIX / JWT
   A PKIX or JWT PublicKey can be created by passing in the raw key material, a key ID, and the key’s SignatureAlgorithm (see [list of supported SignatureAlgorithms](https://github.com/grafeas/kritis/blob/master/pkg/attestlib/signature_algorithm.go#L24)). Note that if the key ID is left as an empty string, a key ID will be generated based on the DER of the key material.
   #### PKIX
   ```
   publicKey := `-----BEGIN PUBLIC KEY BLOCK-----
   `
   key, err := NewPkixPublicKey([]byte(publicKey), “some-key-id”, EcdsaP256Sha256)
   ```
   
   #### JWT
   ```
   publicKey := `-----BEGIN PUBLIC KEY BLOCK-----
   `
   key, err := NewJwtPublicKey([]byte(publicKey), “some-key-id”, EcdsaP256Sha256)
   ```

2. Create a Verifier.

   Create a Verifier using the `NewVerifier` constructor, passing in the image digest you are checking and a slice of PublicKeys.
   
   ```
   publicKeys := []PublicKey{ ... }
   image := "gcr.io/foo@sha256:bar"
   verifier := NewVerifier(image, publicKeys)
   ```

3. Call VerifyAttestation.

   Verify an Attestation by passing it to the Verifier’s `VerifyAttestation` method. The method will first check that the Verifier holds a public key that verifies the Attestation's signature. It then extracts data from the Attestation's payload, including the image name and digest. It checks that the image name and digest match the `image` you are verifying.
   
   If either step fails, the method returns an error:
   
   ```
   if err := verifier.VerifyAttestation(attestation); err != nil {
        // attestation could not be verified
   }
   ```
   
   ### JWT
   For JWT, the `VerifyAttestation` method additionally checks for the well-formedness of the JWT. In the header, it checks that the `crit` field is not populated; the `typ`, `kid`, and `alg` fields must be populated, but they are not used to verify the signature. 
   
   The payload and signature are extracted from their respective sections of the JWT, and are used to cryptographically verify the signature.
