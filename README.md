# Energon
Energon is a traits contract that resolves the power of cryptographic libraries (inputs) into a single generalized API (output). Inspired by [`Kyber`](https://github.com/drand/kyber)


## Concept
- Inputs specified at compile time via feature flag(s) may be selected based on supported architectures, performance, or other considerations.
- Output needs to be combined into a Scheme trait to perform static dispatch, e.g. [`Drand Scheme`](/src/drand/traits.rs#L16)

```
├── backends
│   ├── <curve_A_crate_X>   --feature <A_X>  │
│   │   ├── g1                               │
│   │   ├── g2                               │
│   │   └── scalar                           │
│   ├── <curve_B_crate_Y>   --feature <B_Y>  │
│   │                                        │
│   ├──   :       [INPUTS]                   │
│   └────────────────────────────────────────┘            
│                  
└───────── traits [OUTPUT]
                      |
┌────batteries        |
│                     |
├──Drand(Cyber)────── | ────────────┐
│    ├── ecies        |             │
│    ├── poly         |             │  
│    ├───lib───── [SCHEME] ───────────────> [APP]
│    ├── schnorr                    │
│    ├── tbls                       │
│    └──  :                         │
├───────────────────────────────────┘
├──  :                    
```

## Features
- bls12381_arkworks
- bls12381_blstrs
- bn254_arkworks

## Roadmap
- [x] bn254 curve

## Security Warnings
This library does not make any guarantees about constant-time operations, memory access patterns, or resistance to side-channel attacks.

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>
<br/>
<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
