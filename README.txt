This is a class project for implementing a secure channel.
SETUP - 
We assume that the client has already been authenticated in some way,
likely via password. Client is given the server's public key, server is
given its own private key. I loosely follow a Diffie Hellman TLS Handshake
protocol to ensure various facets of security.

THREATS AND HOW I PROTECT AGAINST THEM -
MITM attacks are a possible problem throughout. Although we know the client
is authenticated, I gave him an RSAKeyPair so that we can continue verifying
his identity, to ward against MITM attacks. Both client and server sign their
key exchange messages before authentication is complete.

Forward Secrecy is guaranteed by incorporating random numbers for the session 
key. The master secret is the hash of server's random number, client's random
number, and the secret derived from Diffie Hellman exchange. Thus the session
key will be different every time. 

We check that the values used for Diffie Hellman are the same by verifying
that the eventual shared secret is the same. This is done by sending 
PRF_k(random_numbers, finished message) to each other and verifying that 
they are the same. (k is the eventual shared secret).

A vulnerability that remains - we do not use certificate authorities. We are
unsure if the public keys that are exchanged are indeed valid.

Initial methods are encrypted by public key to ensure secrecy before 
authentication, but after authentication, we use StreamCipher with nonces. This
is because asymmetric encrypt and decrypt is slower, so we only do that for 
authentication. After authentication, we use symmetric encryption which is 
much faster, and more suitable for bulk data. Nonce prevents some MITM attacks as
the same message will produce a different encrypted message every time.
We use a counter of messages sent and received (appended to message before 
encryption) to guarantee in-order message delivery. Otherwise null is returned.