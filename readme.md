Requires Futures and async/await which are currently only available on nightly.

```
alias scat='rustup run nightly cargo run --example scat'

scat generate scat_keypair_server
scat generate scat_keypair_client

# server
scat listen scat_keypair_server 4444 $(scat getpub scat_keypair_client)

# client in another terminal
scat connect scat_keypair_client <local-ip>:4444 $(scat getpub scat_keypair_server)
```
