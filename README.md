# Chachaware
An educational ransomeware experiment. It doens't contact any servers when encrypting a target and easily maxes out disk IO.
The following things where the design goals:
- Don't contact any servers but allow recovery.
- Encrypt the target as fast as possible using chacha and a goroutine pool.
- Use modern cryptography to make recovery without key as difficult as possible.

## How does it work?
When chachaware is started it does the following things:
- Generate a random X25519 key pair. (recoveryPriv, recoveryPub)
- Forget the recoveryPriv and store the recoveryPub.
- Do a key exchange with another X25519 key. (storedPriv)
- Use HKDF with sha256 on the result of the key exchange and use the result as the secret to encrypt the files.
- Then start scanning the disk for target files and encrypt them using chacha20. (without poly1305 because we don't need authentication but do need performance)

## Recovery
Recovering the secret is possible using the following steps:
- Send the recoveryPub to the distributor.
- The distributor will do a key exchange between recoveryPub and storedPriv.
- After doing HKDF with sha256 the secret is recovered.
- Decrypt the files using the secret.

# Possible improvements
- Use snappy to compress files before encrypting. This would move some of the work from the disk to the cpu and would probably speed up chachaware by ~20-80%
