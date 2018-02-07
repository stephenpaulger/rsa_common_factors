# RSA Common Factor Attack Demonstration

In 2012 two groups of researchers demonstrated that a significant number of SSL certificates in use on the web were generated with weak random number generators. They were able to recreate the private keys just using the public key.

Certificates that share a randomly generated prime as another key elsewhere on the web could be factored with the computationally inexpensive greatest common denominator algorithm rather than having to use an expensive brute-force approach.

The problem has been described very well by Seth Schoen [Understanding Common Factor Attacks:
An RSA-Cracking Puzzle](http://www.loyalty.org/~schoen/rsa/). He also provides a sample set of RSA public keys some of which contain common factors.

This code generates the private keys for that challenge set.