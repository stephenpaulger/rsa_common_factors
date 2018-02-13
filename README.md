# RSA Common Factor Attack Demonstration

__spoiler alert: if you want to complete the challenge yourself, don't read the
code in this repository__

In 2012 two groups of researchers demonstrated that a significant number of SSL
certificates in use on the web were generated with weak random number
generators. They were able to recreate the private keys just using the public
key.

Certificates that share a randomly generated prime as another key elsewhere on
the web could be factored with the computationally inexpensive greatest common
denominator algorithm rather than having to use an expensive brute-force
approach.

The problem has been described very well by Seth Schoen [Understanding Common
Factor Attacks: An RSA-Cracking Puzzle][1]. He also provides a sample set of RSA
public keys some of which contain common factors.

This code generates the private keys for that challenge set.


## Running the demonstration

First download [the challenge zip][2] from Seth Schoen's page and unzip it.

Then you can run...

    go install github.com/stephenpaulger/rsa_common_factors
    
to install the program.

Then `cd` to the challenge directory you extracted from the zip, it will 100
.pem and .bin files. Run `rsa_common_factors` and it should tell you it has
extracted a number of private keys. Those keys can be used to decrypt the
associated .bin files.


## Issues

 * You must run the program from inside the directory as it looks for `*.pem` in
   the current directory. This would be better with a command line argument to
   the directory or allowing you to list the files on the command line.
 * For one hundred 1024-bit public keys the program is relatively fast on a
   normal computer. However, the more public keys being considered the slower
   the program will run and the larger the memory requirement. I don't think the
   researchers in 2012 described how they dealt with looking at hundreds of
   thousands of public keys.
 * The code is probably not idiomatic Go.


## Further Reading

 * [factorable.net](https://factorable.net/)


[1]: http://www.loyalty.org/~schoen/rsa/
     "Understanding Common Factor Attacks: An RSA-Cracking Puzzle"
[2]: http://www.loyalty.org/~schoen/rsa/challenge.zip
     "RSA-cracking challenge zip"