age-plugin-fido -- draft fido plugin for age(1)
===

- WARNING: early draft, likely buggy, protocol not finalized
- WARNING: useful only for symmetric encryption to self
- WARNING: works only with fido2 keys using hmac-secret
- WARNING: does not work with u2f-only keys
- WARNING: look behind you, a three-headed monkey!
- WARNING: usability issues with multiple fido keys
- WARNING: not actually tested with age(1) yet

Plugin specification: https://hackmd.io/@str4d/age-plugin-spec


Example
---

Generate an identity:

```none
   $ ./age-plugin-fido
# tap fido2 device
<  age1fido1yvzqylncrhhrnw8sz64shsg34jdeeths2h70kfw7hqqgznf26ke55y972xws6v74cdy2twsjss77g2xzwfkweejasgfkny6qe2fm64q0aqv5p
<  AGE-PLUGIN-FIDO-1YVZQYLNCRHHRNW8SZ64SHSG34JDEETHS2H70KFW7HQQGZNF26KE55Y972XWS6V74CDY2TWSJSS77G2XZWFKWEEJASGFKNY6QE2FM64QGMZC3C
```

Encapsulate a key:

```none
   $ ./age-plugin-fido --age-plugin=recipient-v1
>  -> add-recipient age1fido1yvzqylncrhhrnw8sz64shsg34jdeeths2h70kfw7hqqgznf26ke55y972xws6v74cdy2twsjss77g2xzwfkweejasgfkny6qe2fm64q0aqv5p
>  -> wrap-file-key
>  4bgH0XAZjfFoWzu9kPEc1X3LLDtrJhqsVzKbrdpfFtw=
>  -> done
# tap fido2 device
<  -> recipient-stanza 0 fido 7bupApLfkhzCgdmpgM6PcC1uDEIm3QZeSVjg2rgE3Ck= wx3Sr82kfmOQttx7ND7ic2uCpmxrA5Es6s+GUb9uAfM=
<  DiI1KqY+rLlliM0dUBPWwjJtBNWC2k9V3hFheWZ2izI2wPP/q1mvftAhsixI6zPY
<  dPjOM5s812VOgccOjJl51g==
<  -> done
```

Decapsulate the key:

```none
   $ ./age-plugin-fido --age-plugin=identity-v1
>  -> add-identity AGE-PLUGIN-FIDO-1YVZQYLNCRHHRNW8SZ64SHSG34JDEETHS2H70KFW7HQQGZNF26KE55Y972XWS6V74CDY2TWSJSS77G2XZWFKWEEJASGFKNY6QE2FM64QGMZC3C
>  -> recipient-stanza 0 fido 7bupApLfkhzCgdmpgM6PcC1uDEIm3QZeSVjg2rgE3Ck= wx3Sr82kfmOQttx7ND7ic2uCpmxrA5Es6s+GUb9uAfM=
>  DiI1KqY+rLlliM0dUBPWwjJtBNWC2k9V3hFheWZ2izI2wPP/q1mvftAhsixI6zPY
>  dPjOM5s812VOgccOjJl51g==
>  -> done
# tap fido2 device
<  -> file-key 0
<  4bgH0XAZjfFoWzu9kPEc1X3LLDtrJhqsVzKbrdpfFtw=
<  -> done
```


Format
---

Identity and recipient share the same payload, a FIDO2 credential id
created with relying party id `x-age://fido`.  Identity is encoded with
bech32 human-readable part `AGE-PLUGIN-FIDO-`, and recipient is encoded
with `age1fido`.

Recipient stanza has form:

```none
fido <base64-credhash> <base64-salt>
<base64-ciphertext>
```

- `<base64-credhash>` is the whitespace-free base64 encoding of the
  SHA-256 hash of:

  - `AGEFIDO1` (US-ASCII text)
  - the 2-byte big-endian encoding of the number of bytes in the
    credential id
  - the credential id

- `<base64-salt>` is the whitespace-free base64 encoding of a 32-byte
  salt chosen independently uniformly at random for each wrapped key

- `<base64-ciphertext>` is the line-folded base64 encoding of the
  ChaCha20-HMACSHA256-SIV ciphertext wrapping a key, with the
  credential id as associated data, under HMAC secret key obtained from
  the device with the given credential id and salt

The identity and recipient store the same information, the credential
id -- there is no private/public separation of powers.
