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

## Compatibility

The agent should be able to provide keys to PuTTy clients immendiately
after its started. Make sure to run the agent non-elevated, otherwise
it won't be able to service non-elevated PuTTy clients.

Furthermore, cngeant provides ssh-agent services via
a cygwin (think Git for Windows) and an AF_UNIX socket.
Both are created in your temp folder and are named `cngeant.cygsock`
and `cngeant.sock` respectively.

The ssh client distributed with Git for Windows should be able to use the cygwin
socket as soon as it picks up the SSH_AUTH_SOCK environment variable.
The shell picks the variable immediately, it should be sufficient restart your
applications after starting cngeant for the first time.

The AF_UNIX socket can be used by WSL's ssh client. Add the following to your
`~/.bashrc` file.

    export SSH_AUTH_SOCKET=/mnt/c/Users/$USER/AppData/Local/Temp/cngeant.sock

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
