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

Generate an identity:

```none
   $ ./age-plugin-fido
   age1fido1ggt3ny6u8juu3hdz4cgmpczpq4zwwd6xz7u6q83wv7m2duessq8q4kuadx
   AGE-PLUGIN-FIDO-1GGT3NY6U8JUU3HDZ4CGMPCZPQ4ZWWD6XZ7U6Q83WV7M2DUESSQ8QYQ8VCQ
```

Encapsulate a key:

```none
   $ ./age-plugin-fido --age-plugin=recipient-v1
>  -> add-recipient age1fido1ggt3ny6u8juu3hdz4cgmpczpq4zwwd6xz7u6q83wv7m2duessq8q4kuadx
>  -> wrap-file-key
>  4bgH0XAZjfFoWzu9kPEc1X3LLDtrJhqsVzKbrdpfFtw=
>  -> done
# tap u2f device
<  -> recipient-stanza 0 fido age1fido1ggt3ny6u8juu3hdz4cgmpczpq4zwwd6xz7u6q83wv7m2duessq8q4kuadx 9CJdH4iysYo25AWhepxI0m3LhuXtU11OVG1hqK8Xk9QedEM0fAW9KTdMUMp6ZA8tE2Ttq6HIjAq5VwoISKf3tg==
<  owECAyYgAX0ktDwa01pTwL6jGJxQhMMjNW5AMB6D4kOr6XxqT5wGr4ojuazJARtN
<  uerlt7Zen8yjg503VQHxuo9/lYAFbS4=
<  -> done
```

Decapsulate the key:

```none
   $ ./age-plugin-fido --age-plugin=identity-v1
>  -> add-identity AGE-PLUGIN-FIDO-1GGT3NY6U8JUU3HDZ4CGMPCZPQ4ZWWD6XZ7U6Q83WV7M2DUESSQ8QYQ8VCQ
>  -> recipient-stanza 0 fido age1fido1ggt3ny6u8juu3hdz4cgmpczpq4zwwd6xz7u6q83wv7m2duessq8q4kuadx 9CJdH4iysYo25AWhepxI0m3LhuXtU11OVG1hqK8Xk9QedEM0fAW9KTdMUMp6ZA8tE2Ttq6HIjAq5VwoISKf3tg==
>  owECAyYgAX0ktDwa01pTwL6jGJxQhMMjNW5AMB6D4kOr6XxqT5wGr4ojuazJARtN
>  uerlt7Zen8yjg503VQHxuo9/lYAFbS4=
>  -> done
# tap key
<  -> file-key 0
<  4bgH0XAZjfFoWzu9kPEc1X3LLDtrJhqsVzKbrdpfFtw=
<  -> done
```
