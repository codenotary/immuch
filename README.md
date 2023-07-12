# ImmuCh - Immutable Communication Channel Tool

Immuch is a tool written in Golang for secure communication backed by [immudb Vault service](https://vault.immudb.io/). It implements a simple message sending and receiving while guaranteeing tamperproof exchange.

Message can be sent either in plain text, encrypted with symmetric AES key or making use of PGP public/private key infrastructure.

## What you need to fire it up
1. Register on [https://vault.immudb.io/](https://vault.immudb.io/) and get your API key
2. Exchange your API key with the other party
3. (Optional but recommended) Generate your AES or PGP keys for message encryption
4. Get the ImmuCh by building ir from source or getting an already compiled binary

## Generating keys
To keep your data secure we encourage to use an additional security layer by using your own encryption keys either AES or PGP.

### Generating AES key
AES (Advanced Encryption Standard) is a symmetric block cipher standardized by NIST. It has a fixed data block size of 16 bytes. Its keys can be 128, 192, or 256 bits long.

Given the above the you can start with a key in a length of 16 characters
```
date +%s | sha256sum | base64 | head -c 16 ; echo
```

### Generating a PGP key
Start with generating a new keypair. You will be asked to protect it with a password
```
gpg --gen-key
```

Export the public and private keys as separated files from the `pubring.kbx` keyring
```
gpg --export "Kristaps <kristaps@codenotary.com>" > ~/.gnupg/pubkey.asc
gpg --export-secret-key "Kristaps <kristaps@codenotary.com>" > ~/.gnupg/private.gpg
```
## Running it
First you will need to setup your environment based on the encryption chosen. Running the `setup` command allows you to make up your configuration.

```
./immuch -h

ImmuCh is a secure CLI messager making use of immudb Vault as a backend:

It enable two parties to communicate securely by using a trusted central authority for exchanging their messages.

immudb Vault guarantees integrity of contents saved by a mathematical proof.

Usage:
  immuch [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  receive     Receive an immutable message
  send        Send out an immutable message
  setup       Setup your configuration

Flags:
      --config string   config file (default is $HOME/.immuch.yaml)
  -h, --help            help for immuch
  -t, --toggle          Help message for toggle
```

You can start simple by just setting your the API key for Vault
```
./immuch setup --vault-key <your-vault-key>

./immuch send "Hi there!"
Using config file: /home/u/.immuch.yaml
2023/07/12 11:09:34 !!! sending in plain text
Wednesday, 12-Jul-23 11:09:34 EEST sent: anonymous ---> Hi there!
```

To receive the message on the other end just use the `receive` command
```
./immuch receive
Using config file: /home/u/.immuch.yaml
Wednesday, 12-Jul-23 11:09:34 EEST received: anonymous ---> Hi there!

```

To make use of AES encryption add the required configuration based on your generated AES key and set the flag to encrypt it
```
./immuch setup --enc-aes ZTg5MGM4NzM1MDFm

/immuch send "Hi there encrypted with AES" --encrypt-aes
Using config file: /home/u/.immuch.yaml
Wednesday, 12-Jul-23 11:14:30 EEST sent: anonymous ---> Hi there encrypted with AES
```

To receive it back once again just use the `receive` command. It will automatically recognize the type of encryption as long as you have your key configured on the receiving end.
```
./immuch receive
Using config file: /home/u/.immuch.yaml
Wednesday, 12-Jul-23 11:14:30 EEST received: anonymous ---> Hi there encrypted with AES
```

To enable encryption with PGP keys configure the ImmuCh tool with the following parameters.
```
./immuch setup --enc-pgp-pub ~/.gnupg/pubkey.asc --enc-pgp-priv ~/.gnupg/private.gpg --enc-pgp-passphrase password123

./immuch send "hi pgp encrypted 1" --encrypt-pgp
Using config file: /home/u/.immuch.yaml
Wednesday, 12-Jul-23 11:26:53 EEST sent: anonymous ---> Hi! This is PGP encrypted

./immuch receive
Using config file: /home/u/.immuch.yaml
Wednesday, 12-Jul-23 11:26:53 EEST received: anonymous ---> Hi! This is PGP encrypted
```

As you can see all the previous messages were sent without any identity. This can be simply configured with the `--identity` flag within the setup.
```
./immuch setup --identity Kristaps
```

The configuration in the end would look like this
```
cat ~/.immuch.yaml
enc_key_aes: ZTg5MGM4NzM1MDFm
enc_key_pgp_passphrase: password123
enc_key_pgp_priv: /home/u/.gnupg/private.gpg
enc_key_pgp_pub: /home/u/.gnupg/pubkey.asc
identity: Kristaps
vault_key: <vault-key-here>
```
