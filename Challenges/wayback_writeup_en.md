# Forensic Analysis — "V1" Challenge
**Category:** Cryptography / Reverse Engineering  
**Platform:** HackTheBox  
**Analyst:** SOC Analyst  
**Analysis Date:** 2026-02-19  
**Estimated Severity (real-world context):** High  

---

## 1. Executive Summary

Two artifacts were received for analysis: an ELF x86-64 binary named `V1` and a Python decryption script (`decrypt.py`). The objective of the exercise is to recover a lost credential by analyzing the behavior of the password generator and the available cryptographic material.

The primary finding is that the password generator presents a **critical weakness in entropy generation**: the seed of the pseudorandom number generator (PRNG) is deterministically derived from the system date and time at execution, which reduces the credential search space to a bounded and fully enumerable set.

---

## 2. Analyzed Artifacts

| Artifact | Type | SHA-256 Hash (illustrative) | Notes |
|---|---|---|---|
| `V1` | ELF 64-bit LSB PIE executable | — | Password generator. Not stripped. |
| `decrypt.py` | Python 3 script | — | Implements AES-CBC decryption with PKCS7 padding |

---

## 3. Static Analysis of the `V1` Binary

### 3.1 Artifact Identification

```
$ file V1
V1: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

The binary is **not stripped**, which facilitates symbol and function name recovery during disassembly tool analysis.

Identified compiler: `GCC 14.2.1`. The source filename embedded in the debug sections is `Wayback.cpp` — a forensically relevant detail, as it suggests an intentional reference to the concept of "time travel", consistent with the vulnerability present in the binary.

### 3.2 Relevant Imports and System Calls

By analyzing dynamic imports via `readelf` and `objdump`, the following functions of special interest were identified:

| Function | Library | Relevance |
|---|---|---|
| `time` | libc | Retrieves the current system timestamp |
| `localtime` | libc | Converts the timestamp into a decomposed `tm` structure |
| `srand` | libc | Initializes the PRNG with a seed |
| `rand` | libc | Generates pseudorandom values |

The combined presence of `time → localtime → srand → rand` in the execution flow is a classic pattern of **weak PRNG initialization**, and constitutes by itself a red flag in any security-oriented code review.

### 3.3 Identified Strings (`strings`)

Static string analysis reveals:

- Character sets used for charset construction: lowercase letters, uppercase letters, special symbols (`!@#$%^&*_+`), and digits (`0123456789`).
- User interaction messages: password length, inclusion of symbols and numbers.
- Error string: `basic_string::append`, consistent with C++ `std::string` usage.

### 3.4 `generate_password` Function — Flow Analysis

Disassembly of the main generation function reveals the following behavior:

1. **Time retrieval:** `time(NULL)` is called to obtain the current UNIX timestamp.
2. **Time decomposition:** the timestamp is converted via `localtime()` into its individual components (seconds, minutes, hours, day, month, year).
3. **Seed computation:** the fields of the `tm` structure are combined through 32-bit integer arithmetic operations (multiplications and additions) to produce a single integer value passed to `srand()`.
4. **Charset construction:** a string is built with the character groups selected according to user input parameters.
5. **Password generation:** for each position, `rand()` is called and a modulo operation is applied over the charset length to select the corresponding character.

> **Critical observation:** the use of `rand()` / `srand()` from the C standard library is **not suitable for cryptographic purposes**. This function produces predictable sequences once the seed is known. Combined with the fact that the seed is directly derived from the date and time, the generated password is **fully reproducible** if the moment of generation is known or can be bounded.

---

## 4. Analysis of `decrypt.py`

The script implements an **AES-256-CBC** decryption scheme:

- **IV:** the first 16 bytes of the encrypted message.
- **Key:** the user-supplied password, zero-padded to 32 bytes.
- **Padding:** PKCS7.

The ciphertext is hardcoded into the script itself as a hexadecimal value. This is relevant because it confirms that the cryptographic material is available for offline analysis, removing any dependency on an external service.

---

## 5. Threat Modeling / Attack Vector

### Known conditions

| Parameter | Value |
|---|---|
| Password length | 20 characters |
| Charset | Alphanumeric + symbols |
| Time window | Two specific days (bounded) |
| Encryption algorithm | AES-256-CBC |
| Cryptographic material | Available (ciphertext + IV hardcoded) |

### Search Space Reduction

Without the PRNG vulnerability, the theoretical search space for a 20-character password over a charset of ~72 symbols would be on the order of **72²⁰ ≈ 10³⁷** — completely infeasible by brute force.

However, given that:

- The seed is derived from a timestamp with **second-level** granularity,
- The time window is bounded to **48 hours** (172,800 seconds),

the effective search space is reduced to **172,800 candidates** — fully enumerable in seconds on modern hardware.

---

## 6. Applied Analysis Methodology

```
[Reconnaissance]
      │
      ▼
[Static binary analysis]
 - file, strings, readelf, objdump
      │
      ▼
[Identification of time→srand→rand pattern]
      │
      ▼
[Reverse engineering of the seed computation]
 - Disassembly analysis of generate_password
 - Algorithm reproduction in a controlled environment
      │
      ▼
[Model validation]
 - Execution environment simulation with spoofed time
 - Output matching verification between real binary and model
      │
      ▼
[Search space enumeration]
 - Iteration over all 172,800 possible timestamps
 - Password candidate generation per timestamp
      │
      ▼
[AES-CBC decryption attempt]
 - Verification via absence of padding exception
      │
      ▼
[Credential and message recovery]
```

---

## 7. Lessons Learned and Recommendations

### 7.1 Use of a Cryptographically Insecure PRNG

**Finding:** The C standard library `rand()` generator is a low-quality deterministic PRNG, unsuitable for cryptographic use.

**Recommendation:** Use cryptographically secure randomness sources:
- Linux: `/dev/urandom`, `getrandom(2)`
- Libraries: `RAND_bytes()` (OpenSSL), `secrets` (Python), `std::random_device` with a CSPRNG backend

### 7.2 Seed Derived from Predictable Information

**Finding:** Deriving the PRNG seed from the system timestamp introduces a prediction window proportional to the uncertainty about the generation moment.

**Recommendation:** Never derive cryptographic seeds from temporal information or other low-entropy values. The seed must be obtained directly from an operating system entropy source.

### 7.3 Encryption Key Padded with Null Bytes

**Finding:** The decryption script pads the password with `\x00` bytes up to 32 bytes if it is shorter. This effectively reduces the entropy of the AES key.

**Recommendation:** Derive cryptographic keys from passwords using an appropriate KDF: **PBKDF2**, **bcrypt**, **scrypt**, or **Argon2**.

### 7.4 Cryptographic Material Hardcoded in Source Code

**Finding:** The ciphertext and IV are hardcoded in the Python script, accessible to anyone with access to the artifact.

**Recommendation:** Encrypted materials should be stored separately from code and preferably transmitted through secure channels, not stored in plaintext within a repository or binary.

---

## 8. Indicators of Compromise (IOCs) — Challenge Context

| Type | Value |
|---|---|
| Ciphertext (hex) | `ad24426047b0ff...` |
| IV (first 16 bytes of ciphertext) | Embedded within the ciphertext |
| Generation time window | 2013-12-10 to 2013-12-11 |
| Source filename in binary | `Wayback.cpp` |

---

## 9. Conclusion

This challenge illustrates in a didactic way one of the most common and critical mistakes in cryptographic software design: **relying on a weak PRNG and a low-entropy seed to generate secret material**. The combination of binary static analysis, algorithm reverse engineering, and brute-force attacks over a reduced search space allows the original credential to be recovered efficiently.

From a security analyst's perspective, this type of vulnerability is particularly dangerous in the context of cryptocurrency wallets, password managers, or any tool that generates cryptographic secrets, since the impact of a breach can be **irreversible** — resulting in permanent fund loss or permanent data exposure.

---

*Document generated for educational purposes in the context of HackTheBox. Does not contain explicit solutions.*
