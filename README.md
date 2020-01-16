# Crypto Box

Java approximation:

- git clone https://github.com/typelogic/cryptobox
- cd cryptobox
- make

The [box7.c](https://asciinema.org/a/wzemICIFMNh9eWujMxtROpeb1) libsodium test case is an illustrative example.

The java sample is an approximation because the sender is only specifying the receiver's public key. Unlike what
was done in `box7.c` in the below snippet:

```c
ret = crypto_box(c, m, mlen + crypto_box_ZEROBYTES, n, bobpk, alicesk);
//                                                       ^       ^  
//                                                       |       |
//                                                       |       |_ sender's secret key
//                                                       |_ receiver's public key
```

To clarify:
- `Box` versus `Sealed Box`
- When to use ephemeral key pairs
- When and how to correctly use `nonce` 
- `MITM` vulnerability
- Is it possible to insert *X.509* certificate into the flow? 
- How to generate the 32 bytes keypair purely in Java
- Clarify the rationale of libsodium cryptobox versus Java's `import java.security.*` 

Reference:
- https://stackoverflow.com/questions/42456624/how-can-i-create-or-open-a-libsodium-compatible-sealed-box-in-pure-java
- https://crypto.stackexchange.com/questions/60609/what-is-the-difference-between-a-sealed-box-and-a-normal-box-in-libsodium
- https://crypto.stackexchange.com/questions/52912/how-safe-are-libsodium-crypto-boxes
