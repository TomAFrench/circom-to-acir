# `circom-to-acir`

Converts from Circom's `.r1cs` to ACIR. An ABI for compatibility with Noir tooling is also generated.

## Known issues

- `circom-to-acir` will panic in the case where any of the circuit's inputs are optimized out from the circuit.
  - Noir enforces that no input may be optimised out so ABI generation doesn't know how to deal with these.
  - Can be fixed later to write these witness values to some scratch space in the witness map.
