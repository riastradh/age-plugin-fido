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
<  age1fido1ptwc54q9d6juf5v7utjegu89pfystqjdvzka9njuvsdxam0g7836fl25lemuw39zn7vl2j0vtx4zprg3c4rkqkusk82p0s4yz3u2kkq83xgqv
<  AGE-PLUGIN-FIDO-1PTWC54Q9D6JUF5V7UTJEGU89PFYSTQJDVZKA9NJUVSDXAM0G7836FL25LEMUW39ZN7VL2J0VTX4ZPRG3C4RKQKUSK82P0S4YZ3U2KKQQHYU94
```

Encapsulate a key:

```none
   $ ./age-plugin-fido --age-plugin=recipient-v1
>  -> add-recipient age1fido1ptwc54q9d6juf5v7utjegu89pfystqjdvzka9njuvsdxam0g7836fl25lemuw39zn7vl2j0vtx4zprg3c4rkqkusk82p0s4yz3u2kkq83xgqv
>  -> wrap-file-key
>  4bgH0XAZjfFoWzu9kPEc1X3LLDtrJhqsVzKbrdpfFtw=
>  -> done
# tap fido2 device
<  -> recipient-stanza 0 fido TSIPatlIgzGOndSxgU9ZIP8ht1wMhrmtvK40LKqe9Ns= 2ej1C6wjwzM+1xjznkIxlhI6SSudWZnJQ+DB29yEFh0=
<  XbY6wJxvFVJZllDFFDtxDXUqwZfBdr3sIZyMYWC1KlYIK0NB4/MSKwu9HJDcvYyC
<  GmU9ISKeaF4C8+pkFJHzMw==
<  -> done
```

Decapsulate the key:

```none
   $ ./age-plugin-fido --age-plugin=identity-v1
>  -> add-identity AGE-PLUGIN-FIDO-1PTWC54Q9D6JUF5V7UTJEGU89PFYSTQJDVZKA9NJUVSDXAM0G7836FL25LEMUW39ZN7VL2J0VTX4ZPRG3C4RKQKUSK82P0S4YZ3U2KKQQHYU94
>  -> recipient-stanza 0 fido TSIPatlIgzGOndSxgU9ZIP8ht1wMhrmtvK40LKqe9Ns= 2ej1C6wjwzM+1xjznkIxlhI6SSudWZnJQ+DB29yEFh0=
>  XbY6wJxvFVJZllDFFDtxDXUqwZfBdr3sIZyMYWC1KlYIK0NB4/MSKwu9HJDcvYyC
>  GmU9ISKeaF4C8+pkFJHzMw==
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
fido <base64-credid> <base64-salt>
<base64-ciphertext>
```

- `<base64-credid>` is the whitespace-free base64 encoding of the
  credential id

- `<base64-salt>` is the whitespace-free base64 encoding of a 32-byte
  salt chosen independently uniformly at random for each wrapped key

- `<base64-ciphertext>` is the line-folded base64 encoding of the
  ChaCha20-HMACSHA256-SIV ciphertext wrapping a key, with the
  credential id as associated data, under HMAC secret key obtained from
  the device with the given credential id and salt

The identity and recipient store the same information, the credential
id -- there is no private/public separation of powers.
