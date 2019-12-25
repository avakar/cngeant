# cngeant

A drop-in replacement for PuTTY's Pageant that uses Windows'
key-store for secure and password-less experience.

The keys can also be stored in your computer's TPM module
for additional security.

## Getting Started

* Get the latest release,
* run it,
* generate a new key pair,
* copy the public key to clipboard, and
* add it among your github SSH keys.

## Features

* Supports SSH2 with RSA or ECDSA (with p256, p384 and p521 curves).
* Private keys are stored per-user. You can't share
  a single key between users.
* Generated private keys are not exportable. You need a fresh key
  for each computer and user account.

## TODO

* Importing private keys.
* Better GUI.
* An icon.
* Notify the user when a key is used.
