# Okamoto–Uchiyama Cryptosystem
This package is implemented according to the pseudo-code and mathematical notations of the following algorithms of the Okamoto–Uchiyama cryptosystem:
 - Key Generation
 - Encryption
 - Decryption

Okamoto–Uchiyama has [additive homomorphic encryption property](https://dl.acm.org/doi/pdf/10.1145/3214303) and is an example of Partially Homomorphic Encryption (PHE). Therefore, the multiplication of ciphers results in the sum of original numbers.

Moreover, it also supports the following PHE functions:
- Homomorphic Encryption over two ciphers
- Homomorphic Encryption over multiple ciphers


## Installation
```sh
go get -u github.com/Mirzazhar/okamoto-uchiyama
```
## Warning
This package is intendedly designed for education purposes. Of course, it may contain bugs and needs several improvements. Therefore, this package should not be used for production purposes.
## Usage & Examples
## LICENSE
MIT License
## References
1. https://en.wikipedia.org/wiki/Okamoto-Uchiyama_cryptosystem
2. https://github.com/mounikapratapa/Okamoto-Uchiyama-implementation
3. https://dl.acm.org/doi/pdf/10.1145/3214303
