# HyPRE
Hybrid proxy re-encryption (HyPRE) for secure data storage and sharing in the cloud.

## 1. Dependencies
- C/CXX compiler: GNU 9.0+
- OpenSSL version "1.1.1f"
- [PBC Library v0.5.14](https://crypto.stanford.edu/pbc/download.html)
- cJSON

## 2. Build
```
cd hypre
mkdir build & cd build
cmake ..
make
```

## 3. Test Results

![](./imgs/cmp_length_scheme-enc.pdf)

![](./imgs/cmp_length_scheme-kgen_s.pdf)

