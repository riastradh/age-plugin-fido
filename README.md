age-plugin-fido -- draft fido plugin for age(1)
===

- WARNING: early draft, likely buggy, protocol not finalized
- WARNING: useful only for symmetric encryption to self
- WARNING: doesn't take advantage of hmac-secret yet
- WARNING: works only with ecdsa/nistp256 u2f/fido keys
- WARNING: look behind you, a three-headed monkey!
- WARNING: usability issues with multiple u2f/fido keys
- WARNING: not actually tested with age(1) yet

Plugin specification: https://hackmd.io/@str4d/age-plugin-spec


Example
---

Generate an identity:

```none
   $ ./age-plugin-fido
   age1fido1ptmsauuez42g3kampn99ge45q75lewlzhjghp2tl053l2tcmtyass9fk46
   AGE-PLUGIN-FIDO-1PTMSAUUEZ42G3KAMPN99GE45Q75LEWLZHJGHP2TL053L2TCMTYASPNJ8QU
```

Encapsulate a key:

```none
   $ ./age-plugin-fido --age-plugin=recipient-v1
>  -> add-recipient age1fido1ptmsauuez42g3kampn99ge45q75lewlzhjghp2tl053l2tcmtyass9fk46
>  -> wrap-file-key
>  4bgH0XAZjfFoWzu9kPEc1X3LLDtrJhqsVzKbrdpfFtw=
>  -> done
# tap u2f device
<  -> recipient-stanza 0 fido MHqLmj4GmOeIjEmMPMSUzeF+197VQ5X6LbhlPqt5R3U= TomzroEmf35W7pvNEgRoKy0fv6vet3l/GaVf1JbgPbkmLftgpsTY/mcR/HhC8wPY8Xy6vDQRxnTrLxB1rW3MqA==
<  owECAyYgAdzQudNiVIRxcIEebBHnT8o9zF3+QXQSoAq1D8aDNQTK6u7Rrr328o2h
<  7uu7JirQK/YSlQiPwgXTDsVTZPlv21c=
<  -> done
```

Decapsulate the key:

```none
   $ ./age-plugin-fido --age-plugin=identity-v1
>  -> add-identity AGE-PLUGIN-FIDO-1PTMSAUUEZ42G3KAMPN99GE45Q75LEWLZHJGHP2TL053L2TCMTYASPNJ8QU
>  -> recipient-stanza 0 fido MHqLmj4GmOeIjEmMPMSUzeF+197VQ5X6LbhlPqt5R3U= TomzroEmf35W7pvNEgRoKy0fv6vet3l/GaVf1JbgPbkmLftgpsTY/mcR/HhC8wPY8Xy6vDQRxnTrLxB1rW3MqA==
>  owECAyYgAdzQudNiVIRxcIEebBHnT8o9zF3+QXQSoAq1D8aDNQTK6u7Rrr328o2h
>  7uu7JirQK/YSlQiPwgXTDsVTZPlv21c=
>  -> done
# tap u2f device
<  -> file-key 0
<  4bgH0XAZjfFoWzu9kPEc1X3LLDtrJhqsVzKbrdpfFtw=
<  -> done
```


Format
---

Identity and recipient share the same payload, a 32-byte cookie chosen
uniformly at random.  Identity is encoded with bech32 human-readable
part `AGE-PLUGIN-FIDO-`, and recipient is encoded with `age1fido`.

Recipient stanza has form:

```none
-> recipient-stanza <n> fido <base64-cookiehash> <base64-credentialid>
<base64-ciphertext>
```

- `<n>` is the file number

- `<base64-cookiehash>` is the whitespace-free base64 encoding of the
  SHA-256 hash of `AGEFIDO1` followed by the 32-byte recipient/identity
  cookie

- `<base64-credentialid>` is the whitespace-free base64 encoding of a
  FIDO credential id

- `<base64-ciphertext>` is the line-folded base64 encoding of the
  [fidocrypt](https://github.com/riastradh/fidocrypt) ciphertext
  wrapping a key, using the recipient (which always starts with
  `age1fido`) as the relying party id

Note: The cookie appears in both the identity and the recipient, but
not in the stanza.  So the identity and recipient are symmetric, and
you need one of them -- in addition to the device -- to decrypt.
