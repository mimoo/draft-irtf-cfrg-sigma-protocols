---
title: "Interactive Sigma Proofs"
category: info

docname: draft-irtf-cfrg-sigma-protocols-latest
submissiontype: independent
number:
date:
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword: ["zero-knowledge", "sigma protocols", "cryptography", "proofs of knowledge"]
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cfrg"
  github: "mmaker/draft-irtf-cfrg-sigma-protocols"
  latest: "https://mmaker.github.io/draft-irtf-cfrg-sigma-protocols/draft-irtf-cfrg-sigma-protocols.html"

author:
  - fullname: "Michele Orrù"
    organization: CNRS
    email: "m@orru.net"
  - fullname: "Cathie Yun"
    organization: Apple, Inc.
    email: "cathieyun@gmail.com"

normative:

informative:
  fiat-shamir:
    title: "draft-irtf-cfrg-fiat-shamir"
    date: false
    target: https://mmaker.github.io/spfs/draft-irtf-cfrg-fiat-shamir.html
  SP800:
    title: "Recommendations for Discrete Logarithm-based Cryptography"
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: https://www.secg.org/sec1-v2.pdf
    date: false
    author:
      -
        ins: Standards for Efficient Cryptography Group (SECG)
  GiacomelliMO16:
    title: "ZKBoo: Faster Zero-Knowledge for Boolean Circuits"
    target: https://eprint.iacr.org/2016/163.pdf
    date: false
    author:
    -
      fullname: "Irene Giacomelli"
    -
      fullname: "Jesper Madsen"
    -
      fullname: "Claudio Orlandi"
  AttemaCK21:
    title: "A Compressed Sigma-Protocol Theory for Lattices"
    target: https://dl.acm.org/doi/10.1007/978-3-030-84245-1_19
    date: false
    author:
    -
      fullname: Thomas Attema
    -
      fullname: Ronald Cramer
    -
      fullname: Lisa Kohl
  BonehS23:
      title: "A Graduate Course in Applied Cryptography"
      target: https://toc.cryptobook.us/
      author:
      -
        fullname: Dan Boneh
      -
        fullname: Victor Shoup
  Stern93:
    title: "A New Identification Scheme Based on Syndrome Decoding"
    target: https://link.springer.com/chapter/10.1007/3-540-48329-2_2
    date: 1993
    author:
      - fullname: "Jacques Stern"
  CS97:
      title: "Proof Systems for General Statements about Discrete Logarithms"
      author:
        - fullname: "Jan Camenisch"
        - fullname: "Markus Stadler"
      target: https://crypto.ethz.ch/publications/files/CamSta97b.pdf
  Maurer09:
      title: "Unifying Zero-Knowledge Proofs of Knowledge"
      author:
        - fullname: "Ueli Maurer"
      target: https://crypto.ethz.ch/publications/files/Maurer09.pdf
      date: 2009

--- abstract

This document describes interactive Sigma Protocols, a class of secure, general-purpose zero-knowledge proofs of knowledge consisting of three moves: commitment, challenge, and response. Concretely, the protocol allows one to prove knowledge of a secret witness without revealing any information about it. All protocols in this document are expressed as proofs of knowledge of a preimage under a group homomorphism, a single abstraction that unifies Schnorr, DLEQ, and Pedersen-style proofs behind one interface.

--- middle

# Introduction

Any Sigma Protocol must define three objects: a *commitment* (computed by the prover), a *challenge* (computed by the verifier), and a *response* (computed by the prover).

Every Sigma Protocol in this document is an instance of one protocol: a proof of knowledge of the **preimage of a group homomorphism**. A proof is fully specified by five objects, described in {{statements}}:

- the **public parameters**: fixed values (such as group generators) shared by everyone and identical across all proofs of the same kind;
- the **witness** `w`: the secret preimage the prover knows;
- the **instance** `X`: the public statement being proven, which may vary from one proof to the next;
- the **homomorphism** `psi`: a group homomorphism mapping the witness to the group;
- the **image function** `f`: a function mapping the instance to the target that `psi` must reach.

The relation being proven is `psi(w) == f(X)`. To define a new Sigma proof, a developer specifies these five objects and nothing else; no protocol code, allocation of variables, or constraint-builder calls are required.

## Core interface

The public functions are obtained relying on an internal structure containing the definition of a Sigma Protocol.

    class SigmaProtocol:
       def new(statement) -> SigmaProtocol
       def prover_commit(self, witness, rng) -> (commitment, prover_state)
       def prover_response(self, prover_state, challenge) -> response
       def verifier(self, commitment, challenge, response) -> bool
       def serialize_commitment(self, commitment) -> bytes
       def serialize_response(self, response) -> bytes
       def deserialize_commitment(self, data: bytes) -> commitment
       def deserialize_response(self, data: bytes) -> response
       # optional
       def simulate_response(self, rng) -> response
       # optional
       def simulate_commitment(self, response, challenge) -> commitment

Where:

- `new(statement) -> SigmaProtocol`, denoting the initialization function. This function takes as input a `statement` (see {{statements}}), the public information shared between prover and verifier. A statement bundles the homomorphism `psi` together with the image `f(X)` derived from the instance.

- `prover_commit(self, witness: Witness, rng) -> (commitment, prover_state)`, denoting the **commitment phase**, that is, the computation of the first message sent by the prover in a Sigma Protocol. This method outputs a new commitment together with its associated prover state, depending on the witness known to the prover, the statement to be proven, and a random number generator `rng`. This step generally requires access to a high-quality entropy source to perform the commitment. Leakage of even just a few bits of the commitment could allow for the complete recovery of the witness. The commitment is meant to be shared, while `prover_state` must be kept secret.

- `prover_response(self, prover_state, challenge) -> response`, denoting the **response phase**, that is, the computation of the second message sent by the prover, depending on the witness, the statement, the challenge received from the verifier, and the internal state `prover_state`. The return value response is a public value and is transmitted to the verifier.

- `verifier(self, commitment, challenge, response) -> bool`, denoting the **verifier algorithm**. This method checks that the protocol transcript is valid for the given statement. The verifier algorithm outputs true if verification succeeds, or false if verification fails.

- `serialize_commitment(self, commitment) -> bytes`, serializes the commitment into a canonical byte representation.

- `serialize_response(self, response) -> bytes`, serializes the response into a canonical byte representation.

- `deserialize_commitment(self, data: bytes) -> commitment`, deserializes a byte array into a commitment. This function can raise a `DeserializeError` if deserialization fails.

- `deserialize_response(self, data: bytes) -> response`, deserializes a byte array into a response. This function can raise a `DeserializeError` if deserialization fails.

The final two algorithms describe the **zero-knowledge simulator**. In particular, they may be used for proof composition (e.g. OR-composition). The function `simulate_commitment` is also used when verifying short proofs. We have:

- `simulate_response(self, rng) -> response`, denoting the first stage of the simulator.

- `simulate_commitment(self, response, challenge) -> commitment`, returning a simulated commitment -- the second phase of the zero-knowledge simulator.

The simulated transcript `(commitment, challenge, response)` must be indistinguishable from the one generated using the prover algorithms.

The abstraction `SigmaProtocol` allows implementing different types of statements and combiners of those, such as OR statements, validity of t-out-of-n statements, and more.

# Sigma Protocols over prime-order groups {#sigma-protocol-group}

The following sub-section presents concrete instantiations of Sigma Protocols over prime-order elliptic curve groups.
It relies on a prime-order elliptic-curve group as described in {{group-abstraction}}.

Valid choices of elliptic curves can be found in {{ciphersuites}}.

Traditionally, Sigma Protocols are defined in Camenisch-Stadler {{CS97}} notation as (for example):

    1. DLEQ(G, H, X, Y) = PoK{
    2.   (x):        // Secret variables
    3.   X = x * G, Y = x * H        // Predicates to satisfy
    4. }

In the above, line 1 declares that the proof name is "DLEQ", the public information (the **instance**) consists of the group elements `(G, X, H, Y)` denoted in upper-case.
Line 2 states that the private information (the **witness**) consists of the scalar `x`.
Finally, line 3 states that the relation that needs to be proven is
`x * G  = X` and `x * H = Y`.

Read in the homomorphism framework of this document, the equations of line 3 say that the map `psi(x) = (x * G, x * H)` sends the witness `x` to the instance `(X, Y)`. The prover shows knowledge of a preimage of `(X, Y)` under `psi`. Every example in this document follows the same pattern.

## Group abstraction {#group-abstraction}

Because of their dominance, the presentation in the following focuses on proof goals over elliptic curves, therefore leveraging additive notation. For prime-order subgroups of residue classes, all notation needs to be changed to multiplicative, and references to elliptic curves (e.g., curve) need to be replaced by their respective counterparts over residue classes.

We detail the functions that can be invoked on these objects. Example choices can be found in {{ciphersuites}}.

### Group {#group}

- `identity()`, returns the neutral element in the group.
- `generator()`, returns the generator of the prime-order elliptic-curve subgroup used for cryptographic operations.
- `order()`: returns the order of the group `p`.
- `random()`: returns an element sampled uniformly at random from the group.
- `serialize(elements: [Group; N])`, serializes a list of group elements and returns a canonical byte array `buf` of fixed length `Ne * N`.
- `deserialize(buffer)`, attempts to map a byte array `buffer` of size `Ne * N` into `[Group; N]`, fails if the input is not the valid canonical byte representation of an array of elements of the group. This function can raise a `DeserializeError` if deserialization fails.
- `add(element: Group)`, implements elliptic curve addition for the two group elements.
- `equal(element: Group)`, returns `true` if the two elements are the same and `false` otherwise.
- `scalar_mul(scalar: Scalar)`, implements scalar multiplication for a group element by an element in its respective scalar field.

In this spec, instead of `add` we will use `+` with infix notation; instead of `equal` we will use `==`, and instead of `scalar_mul` we will use `*`. A similar behavior can be achieved using operator overloading.

### Scalar

- `identity()`: outputs the (additive) identity element in the scalar field.
- `add(scalar: Scalar)`: implements field addition for the elements in the field.
- `mul(scalar: Scalar)`, implements field multiplication.
- `random()`: returns an element sampled uniformly at random from the scalar field.
- `serialize(scalars: list[Scalar; N])`: serializes a list of scalars and returns their canonical representation of fixed length `Ns * N`.
- `deserialize(buffer)`, attempts to map a byte array `buffer` of size `Ns * N` into `[Scalar; N]`, and fails if the input is not the valid canonical byte representation of an array of elements of the scalar field. This function can raise a `DeserializeError` if deserialization fails.

In this spec, instead of `add` we will use `+` with infix notation; instead of `equal` we will use `==`, and instead of `mul` we will use `*`. A similar behavior can be achieved using operator overloading.

## Proofs of preimage of a group homomorphism

All Sigma protocols in this document are instances of a single protocol: a proof of knowledge of the **preimage of a group homomorphism** {{Maurer09}}. This framework, and the specialization to linear relations over prime-order groups used below, is presented in Sections 19.5.3 and 19.5.4 of {{BonehS23}}. Let `H1` and `H2` be two abelian groups of known order and let `psi: H1 -> H2` be a group homomorphism (that is, `psi(a + b) == psi(a) + psi(b)` for all `a, b` in `H1`). Given a target `image` in `H2`, the protocol lets a prover convince a verifier that it knows a witness `w` in `H1` such that `psi(w) == image`, without revealing anything else about `w`.

For prime-order groups, `H1` is the set of witnesses `[Scalar; num_scalars]` under component-wise addition, and `H2` is the set of images `[Group; num_images]` under component-wise addition. The homomorphism `psi` is then a linear map from scalars to group elements (see {{morphism}}), and Schnorr, DLEQ, and Pedersen proofs differ only in the choice of `psi` and `image` (see the examples below).

The `image` is not supplied directly: it is computed from the instance `X` by a function `f`, as `image = f(X)`. Keeping `f` separate from `psi` cleanly divides the fixed structure of the proof (`psi`, built only from public parameters) from the values a malicious prover might try to choose or alter after the fact (the instance `X`). It also makes explicit that the challenge must be bound to the instance `X`, the input of `f`, and never to the image `f(X)`, which need not determine `X` uniquely (see {{security-considerations}}).

### Core protocol

This defines the object `SchnorrProof`. The initialization function `new(statement)` takes as input the statement of {{statements}} and pre-processes it.

### Prover procedures

The prover of a Sigma Protocol is stateful and will send two messages, a "commitment" and a "response" message, described below.

#### Prover commitment

    prover_commit(self, witness, rng)

    Inputs:

    - witness, an array of scalars
    - rng, a random number generator

    Outputs:

    - A (private) prover state, holding the information of the interactive prover necessary for producing the protocol response
    - A (public) commitment message, an element of the homomorphism's codomain, that is, a vector of group elements.

    Procedure:

    1. nonces = [self.statement.Group.ScalarField.random(rng) for _ in range(self.statement.num_scalars)]
    2. prover_state = self.ProverState(witness, nonces)
    3. commitment = self.statement.psi(nonces)
    4. return (prover_state, commitment)

#### Prover response

    prover_response(self, prover_state, challenge)

    Inputs:

        - prover_state, the current state of the prover
        - challenge, the verifier challenge scalar

    Outputs:

        - An array of scalar elements composing the response

    Procedure:

    1. witness, nonces = prover_state
    2. return [nonces[i] + witness[i] * challenge for i in range(self.statement.num_scalars)]

### Verifier

    verify(self, commitment, challenge, response)

    Inputs:

    - self, the current state of the SigmaProtocol
    - commitment, the commitment generated by the prover
    - challenge, the challenge generated by the verifier
    - response, the response generated by the prover

    Outputs:

    - A boolean indicating whether the verification succeeded

    Procedure:

    1. assert len(commitment) == self.statement.num_images and len(response) == self.statement.num_scalars
    2. expected = self.statement.psi(response)
    3. got = [commitment[i] + self.statement.image[i] * challenge for i in range(self.statement.num_images)]
    4. return got == expected

Here `self.statement.image` is the value `f(X)` computed from the instance when the statement was built (see {{statements}}).

### Witness {#witness}

A witness is simply the preimage under `psi`, represented as a list of scalar elements of size `num_scalars`.

    Witness = [Scalar; num_scalars]

### Homomorphism {#morphism}

The homomorphism `psi` is a function from `[Scalar; num_scalars]` to `[Group; num_images]`. It is not serialized or given any canonical encoding by this document; it is simply the function the prover and verifier evaluate. It MUST be a group homomorphism in the witness, that is `psi(a + b) == psi(a) + psi(b)` for all witnesses `a`, `b`.

Over prime-order groups, this means each of the `num_images` outputs is a linear combination of the witness scalars, with group-element coefficients drawn from the public parameters and the instance. For example, a `psi` taking a witness `[x, r]` to a single group element `x * G + r * H` is written directly as:

    def psi(witness):
        x, r = witness
        return [x * G + r * H]

where `G` and `H` are the group elements it closes over. The number of witness scalars `num_scalars` cannot be recovered by evaluating `psi`, so it is recorded alongside it in the statement; every other dimension follows from evaluation.

### Statement {#statements}

A **statement** is the public description of what is being proven. It carries the two functions `psi` and `f`, the instance, and the witness length.

    class Statement:
        Group: groups.Group
        num_scalars: int
        psi                           # function: [Scalar; num_scalars] -> [Group; num_images]
        f                             # function: instance -> [Group; num_images]
        instance: list[Group]         # the public statement X

        @property
        def image(self):
            return self.f(self.instance)

        @property
        def num_images(self):
            return len(self.image)

The relation proven by the statement is

    psi(witness) == f(instance)

To define a Sigma proof, a developer specifies five objects, in plain form, without any allocation or builder calls:

1. the **public parameters**: the fixed group elements (and scalars) that `psi` uses as coefficients, such as generators;
2. the **witness**: a list of `num_scalars` scalars, the secret preimage;
3. the **instance**: a list of group elements, the public statement `X`;
4. the **homomorphism** `psi`: a function of the witness, using only the public parameters and the instance;
5. the **image function** `f`: a function of the instance, returning `[Group; num_images]`.

In most protocols the instance is already the image, so `f` is the identity function. `f` becomes non-trivial when the value that `psi` must reach is a public function of several instance elements (see {{security-considerations}} for the requirements `psi` and `f` must satisfy).

### Ordering and serialization {#ordering}

The witness, instance, image, commitment, and response are **ordered** lists, and their ordering is significant. It is fixed by the definition of the statement and MUST be identical for the prover and the verifier:

- component `i` of the commitment corresponds to output `i` of `psi` and to component `i` of the image `f(instance)`;
- component `j` of the response corresponds to scalar `j` of the witness.

Reordering any of these lists produces a different statement and a proof that will not verify against the original. Because the ordering is part of the statement, it MUST also be reflected in the protocol identifier ({{protocol-id-generation}}) and instance identifier ({{instance-id-generation}}).

Group elements and scalars are serialized with the canonical, fixed-length encodings of {{group}}, concatenated in list order. Concretely, for `SchnorrProof`:

- `serialize_commitment(self, commitment) = self.statement.Group.serialize(commitment)`, producing `Ne * num_images` bytes.
- `serialize_response(self, response) = self.statement.Group.ScalarField.serialize(response)`, producing `Ns * num_scalars` bytes.
- `deserialize_commitment(self, data)` reads exactly `num_images` group elements from `data` using `Group.deserialize`, and raises `DeserializeError` if the length is not `Ne * num_images` or any element is invalid.
- `deserialize_response(self, data)` reads exactly `num_scalars` scalars from `data` using `ScalarField.deserialize`, and raises `DeserializeError` if the length is not `Ns * num_scalars` or any scalar is invalid.

The instance is serialized the same way, as `Group.serialize(instance)` in list order. This canonical encoding is the value that MUST be bound by the Fiat-Shamir challenge (see {{security-considerations}}). Note that the instance, not the image `f(instance)`, is the value serialized and bound.

### Example: Schnorr proofs

The Schnorr proof of knowledge of a discrete logarithm,

    Schnorr(G, X) = PoK{(x): X = x * G}

is specified as:

- public parameters: `G`, a generator;
- witness: `[x]`;
- instance: `[X]`;
- homomorphism: `psi([x]) = [x * G]`;
- image function: `f([X]) = [X]` (the identity).

Concretely, once `G` and `X` are available:

    def psi(witness):
        [x] = witness
        return [x * G]

    statement = Statement(Group, num_scalars=1, psi=psi,
                          f=lambda instance: instance, instance=[X])

It is worth noting that in the above example `[X] == psi([x])`.

### Example: DLEQ proofs

A DLEQ proof proves equality of discrete logarithms,

    DLEQ(G, H, X, Y) = PoK{(x): X = x * G, Y = x * H}

Given group elements `G`, `H` and `X`, `Y` such that `X = x * G` and `Y = x * H`, the statement is:

- public parameters: `G`, `H`;
- witness: `[x]`;
- instance: `[X, Y]`;
- homomorphism: `psi([x]) = [x * G, x * H]`;
- image function: `f([X, Y]) = [X, Y]` (the identity).

The single witness scalar `x` appears in both output components, which is exactly what forces the two discrete logarithms to be equal.

### Example: Pedersen commitments

A representation (Pedersen opening) proof proves knowledge of the opening of a commitment,

    REPR(G, H, C) = PoK{(x, r): C = x * G + r * H}

Given generators `G`, `H` and a commitment `C = x * G + r * H`, the statement is:

- public parameters: `G`, `H`;
- witness: `[x, r]`;
- instance: `[C]`;
- homomorphism: `psi([x, r]) = [x * G + r * H]`;
- image function: `f([C]) = [C]` (the identity).

## Ciphersuites {#ciphersuites}

### P-256 (secp256r1)

This ciphersuite uses P-256 {{SP800}} for the Group.

#### Elliptic curve group of P-256 (secp256r1) {{SP800}}

- `order()`: Return the integer `115792089210356248762697446949407573529996955224135760342422259061068512044369`.
- `serialize([A])`: Implemented using the compressed Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}}; `Ne = 33`.
- `deserialize(buf)`: Implemented by attempting to read `buf` into chunks of 33-byte arrays and convert them using the compressed Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and then performs partial public-key validation as defined in section 5.6.2.3.4 of {{!KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar3}}. This includes checking that the coordinates of the resulting point are in the correct range, that the point is on the curve, and that the point is not the point at infinity.

#### Scalar Field of P-256

- `serialize(s)`: Relies on the Field-Element-to-Octet-String conversion according to {{SEC1}}; `Ns = 32`.
- `deserialize(buf)`: Reads the byte array `buf` in chunks of 32 bytes using Octet-String-to-Field-Element from {{SEC1}}. This function can fail if the input does not represent a Scalar in the range `[0, G.Order() - 1]`.

# Security Considerations {#security-considerations}

Sigma Protocols are special sound and honest-verifier zero-knowledge. These proofs are deniable (without transferable message authenticity).

We focus on the security guarantees of the non-interactive Fiat-Shamir transformation, where they provide the following guarantees (in the random oracle model):

- **Knowledge soundness**: If the proof is valid, the prover must have knowledge of a secret witness satisfying the proof statement. This property ensures that valid proofs cannot be generated without possession of the corresponding witness.

- **Zero-knowledge**: The proof string produced by the `prove` function does not reveal any information beyond what can be directly inferred from the statement itself. This ensures that verifiers gain no knowledge about the witness.

While theoretical analysis demonstrates that both soundness and zero-knowledge properties are statistical in nature, practical security depends on the cryptographic strength of the underlying hash function, which is defined by the Fiat-Shamir transformation. It's important to note that the soundness of a zero-knowledge proof provides no guarantees regarding the computational hardness of the relation being proven. An assessment of the specific hardness properties for relations proven using these protocols falls outside the scope of this document.

## Requirements for defining a statement {#statement-requirements}

A Sigma proof defined as in {{statements}} is only as sound and zero-knowledge as its five objects allow. Implementers and auditors MUST verify the following before deploying a new statement.

- **The homomorphism `psi` MUST be a group homomorphism in the witness.** It may depend only on the public parameters, the witness, and the instance. The construction of {{morphism}} guarantees this for any `psi` built as a linear combination of witness scalars with public group-element coefficients; a `psi` defined by any other means MUST be checked to satisfy `psi(a + b) == psi(a) + psi(b)`.

- **The image function `f` MUST depend only on the public parameters and the instance, never on the witness.** A dependence on the witness would let the target `f(X)` leak secret information or break soundness.

- **Public parameters MUST NOT contain values that a malicious prover can choose or change after observing a proof.** Any such value belongs in the instance, so that it is bound by the challenge. Placing a prover-influenced value among the public parameters (for example, a generator the prover may re-select) breaks soundness.

- **The instance MUST NOT contain private values.** Anything secret belongs in the witness; the instance is public and revealed to the verifier.

- **The challenge MUST be bound to the instance `X`, the input of `f`, and never to the image `f(X)`.** Since `f` need not be injective, two distinct instances `X != X'` may satisfy `f(X) == f(X')`. If only the image were bound, a malicious prover could produce a proof for `X` and later present it as a proof for a different instance `X'` with the same image. Binding the instance itself closes this substitution. The Fiat-Shamir transformation {{fiat-shamir}} MUST therefore absorb the instance, together with the public parameters and the homomorphism `psi`, when deriving the challenge.

## Privacy Considerations

Sigma Protocols are insecure against malicious verifiers and should not be used.
The non-interactive Fiat-Shamir transformation leads to publicly verifiable (transferable) proofs that are statistically zero-knowledge.

# Post-Quantum Security Considerations

The zero-knowledge proofs described in this document provide statistical zero-knowledge and statistical soundness properties when modeled in the random oracle model.

## Privacy Considerations

These proofs offer zero-knowledge guarantees, meaning they do not leak any information about the prover's witness beyond what can be inferred from the proven statement itself. This property holds even against quantum adversaries with unbounded computational power.

Specifically, these proofs can be used to protect privacy against post-quantum adversaries, in applications demanding:

- Post-quantum anonymity
- Post-quantum unlinkability
- Post-quantum blindness
- Protection against "harvest now, decrypt later" attacks.

## Soundness Considerations

While the proofs themselves offer privacy protections against quantum adversaries, the hardness of the relation being proven depends (at best) on the hardness of the discrete logarithm problem over the elliptic curves specified in {{ciphersuites}}.
Since this problem is known to be efficiently solvable by quantum computers using Shor's algorithm, these proofs MUST NOT be relied upon for post-quantum soundness guarantees.

Implementations requiring post-quantum soundness SHOULD transition to alternative proof systems such as:

- MPC-in-the-Head approaches as described in {{GiacomelliMO16}}
- Lattice-based approaches as described in {{AttemaCK21}}
- Code-based approaches as described in {{Stern93}}

Implementations should consider the timeline for quantum computing advances when planning migration to post-quantum sound alternatives.
Implementers MAY adopt a hybrid approach during migration to post-quantum security by using AND composition of proofs. This approach enables gradual migration while maintaining security against classical adversaries.
This composition retains soundness if **both** problems remain hard. AND composition of proofs is NOT described in this specification, but examples may be found in the proof-of-concept implementation and in {{BonehS23}}.

# Generation of the protocol identifier {#protocol-id-generation}

As of now, it is responsibility of the user to pick a unique protocol identifier that identifies the proof system. This will be expanded in future versions of this specification.

# Generation of the instance identifier {#instance-id-generation}

As of now, it is responsibility of the user to pick a unique instance identifier that identifies the statement being proven.

--- back

# Acknowledgments
{:numbered ="false"}

The authors thank Jan Bobolz, Vishruti Ganesh, Stephan Krenn, Mary Maller, Ivan Visconti, Yuwen Zhang for reviewing a previous edition of this specification.

# Test Vectors
{:numbered="false"}

Test vectors will be made available in future versions of this specification.
They are currently developed in the [proof-of-concept implementation](https://github.com/mmaker/draft-zkproof-sigma-protocols/tree/main/poc/vectors).
