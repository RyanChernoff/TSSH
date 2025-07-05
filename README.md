# TSSH
TSSH is a minimal version of a secure shell protocol version 2.0 client based off of the RFC specifications.
It currently only allows for opening a remote shell on port 22 (the default ssh port) via password authenication.
The transport layer only implements ecdh-sha2-nistp256 for both encryption, rsa-sha2-512 for host key signiture verification,
and aes256-ctr for mac-ing. TSSH does not implement compression for packet sending.

# Usage
To use TSSH, compile it with cargo and run the exicutable with either the servers address or username@adress as the first and 
only argument. It will then prompt you for your username (if you did not specify it) and your password after which a shell session will
start.

# Disclaimer
This implementation of ssh is not secure. It does not verify host key's which makes it vulnerable to man in the middle attacks.
TSSH was developed for educational use and should not be used in place of more throughly vetted implementation.
