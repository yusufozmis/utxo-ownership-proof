# zkSTARK Prover for UTXO Ownership

This project implements a zkSTARK prover that validates the ownership of a UTXO (Unspent Transaction Output) with the following guarantees:

- **Existence**: Confirms the UTXO exists on the blockchain.
- **Amount Validation**: Verifies the UTXO's amount exceeds a user-defined threshold \( X \).
- **Non-Spent Status**: Ensures the UTXO has not been previously spent.

### Features:
- **Privacy-Preserving**: Proves UTXO properties without revealing sensitive data.
- **Scalable**: Efficient for large UTXO sets and complex transactions.

### Future Work:
- **Optimizing Computation**: Reduce off-chain computation outside the zk-STARK circuit.
- **Performance Improvements**: Explore FFT-based optimizations over Lagrange Interpolation.
- **User Experience**: Develop a frontend for easier interaction.

**Note**: This is a Proof of Concept (PoC). Do not use in production.
