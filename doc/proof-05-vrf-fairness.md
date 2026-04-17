# Proof-05: VRF Leader Election Fairness

**DO-333 Requirement:** `doc/10-security.md` line 154
**Source:** `doc/04-consensus.md` lines 54–92, `doc/16-verification-plan.md` lines 151–152
**Assumptions used:** A5 (DDH on Ed25519), A8 (honest majority)

---

## Preamble

This document proves that UmbraVox's VRF-based slot leader election is
fair (proportional to stake weight) and provides the statistical test
design for empirical verification.  The analysis assumes honest majority
(A8): honest validators hold > 2/3 of total stake, ensuring that VRF
evaluations are performed honestly and that adversarial stake cannot
systematically bias election outcomes.

---

## 1. VRF Leader Election Mechanism

From `doc/04-consensus.md` lines 54–65:

```
VRF_input = epoch_nonce || slot_number
(proof, output) = VRF_prove(node_secret_key, VRF_input)

sigma_j = effective_stake_j / total_effective_stake
threshold_j = 1 - (1 - f)^{sigma_j}

if VRF_output_normalized < threshold_j:
    node j is slot leader
```

where f = 0.20 (active slot coefficient).

---

## 2. Lemma: VRF Output Uniformity

**Lemma 2.1 (VRF Uniformity).**

Under the DDH assumption (A5), for any fixed input x, the VRF output
VRF(sk, x) is computationally indistinguishable from a uniform random
value in [0, 2^{512}).

**Proof.**  By Theorem 8.1 of Proof-01:

```
Adv^VRF-PR_{ECVRF}(A) ≤ Adv^DDH_{Ed25519}(A') + q_v / 2^{128}
```

where q_v is the number of VRF evaluation queries (notation per Proof-01
§8.3).  For q_v ≤ 2^{64} queries (more than sufficient for any practical
number of slots): Adv ≤ Adv^DDH + 2^{-64} ≈ negl(λ).

After normalisation to [0, 1) via division by 2^{64} (using the first
8 bytes), the output is computationally uniform in [0, 1).  □

---

## 3. Lemma: Independence Across Slots

**Lemma 3.1 (VRF Independence).**

For distinct inputs x₁ ≠ x₂ (i.e., distinct slot numbers within the
same epoch, or slots in different epochs), the VRF outputs VRF(sk, x₁)
and VRF(sk, x₂) are computationally independent.

**Proof.**  The VRF is modelled as a pseudorandom function in the ROM.
Each evaluation VRF(sk, x_i) = hash(cofactor · sk · H(x_i)) where H
maps distinct inputs to distinct curve points with overwhelming probability
(the composite hash-to-curve, which hashes the input via SHA-512 before
applying the Elligator2 map, is modelled as a random oracle; collision
probability is at most q²/2^{252} for q queries, where the Ed25519
prime-order subgroup has order ℓ = 2^{252} + 27742317777372353535851937790883648493
≈ 2^{252}).

For x₁ ≠ x₂: H(x₁) ≠ H(x₂) (with overwhelming probability in the ROM).
The values sk · H(x₁) and sk · H(x₂) are distinct curve points, and
the hash function SHA-512 acts as a random oracle on distinct inputs.

Therefore, VRF(sk, x₁) and VRF(sk, x₂) are computationally independent
random variables.  □

---

## 4. Theorem: Expected Fairness

**Theorem 4.1 (Leader Election Proportionality).**

Let V validators have stake fractions σ₁, …, σ_V with Σσ_j = 1.
Over T slots, the expected number of times validator j is elected leader is:

```
E[count_j] = T · p_j
```

where p_j = 1 - (1 - f)^{σ_j} is the per-slot leader probability.

The variance is:

```
Var[count_j] = T · p_j · (1 - p_j)
```

### Proof

By Lemmas 2.1 and 3.1, VRF outputs across slots are independent and
uniform (for honest validators; A8 ensures > 2/3 of stake is honest).
Validator j is elected in slot s if:

```
VRF_normalized(sk_j, epoch_nonce || s) < threshold_j = 1 - (1-f)^{σ_j}
```

This is a Bernoulli trial with success probability p_j.  Over T
independent slots, count_j follows a Binomial(T, p_j) distribution.

Therefore:
```
E[count_j] = T · p_j
Var[count_j] = T · p_j · (1 - p_j)
```
□

### 4.1 Taylor Expansion (Proportionality)

For small σ_j (many validators, each with small stake fraction):

```
p_j = 1 - (1-f)^{σ_j}
    = 1 - exp(σ_j · ln(1-f))
    ≈ 1 - (1 - σ_j · (-ln(1-f)))
    = σ_j · (-ln(1-f))
    = σ_j · (-ln(0.80))
    ≈ σ_j · 0.2231
```

So for small stakes: p_j ≈ 0.2231 · σ_j, which is **linear in stake**.

The expected leader count is proportional to stake:

```
E[count_j] ≈ T · 0.2231 · σ_j
```

Validators with twice the stake are elected approximately twice as often.

### 4.2 Multi-Leader Slot Analysis

Multiple validators can be elected in the same slot (independent VRF
evaluations).  The expected number of leaders per slot is:

```
E[leaders/slot] = Σ_j p_j = Σ_j (1 - (1-f)^{σ_j})
```

Using the Taylor approximation from §4.1, p_j ≈ (-ln(1-f)) · σ_j:

```
E[leaders/slot] ≈ (-ln(1-f)) · Σ_j σ_j = -ln(1-f) = -ln(0.80) ≈ 0.2231
```

Note that E[leaders/slot] ≈ 0.2231 is the expected *count* (including
multi-leader slots).  The probability of *at least one* leader in a slot
is Pr[≥1] = 1 - ∏_j (1 - p_j) = 1 - ∏_j (1-f)^{σ_j} = 1 - (1-f)^{Σσ_j}
= 1 - (1-f) = f = 0.20 (using Σσ_j = 1).  So roughly 1 in 5 slots has a
leader.  Most leader slots have exactly 1 leader (multi-leader probability
is small when f is small).

---

## 5. Chi-Squared Test Design

### 5.1 Hypotheses

```
H₀: Leader election is proportional to stake.
    Observed frequency ~ Expected frequency for all validators.

H₁: Leader election deviates from proportionality.
```

### 5.2 Test Statistic

```
χ² = Σ_{j=1}^{V} (O_j - E_j)² / E_j
```

where:
- O_j = observed leader count for validator j
- E_j = T · p_j = expected leader count
- V = number of validators

### 5.3 Parameters

```
Degrees of freedom: df = V
Significance level: α = 0.01  (reject H₀ if p-value < 0.01)
Decision: If p-value ≥ 0.01, fail to reject H₀ (fairness holds)

Note: df = V (not V-1) because the O_j are independent Binomial
counts, not a multinomial with fixed total.  Each validator's VRF
evaluation is independent, so the total number of leaders per slot
is random, not constrained.
```

### 5.4 Multiple Seeds

Run the test with 10 different random seeds for the initial epoch nonce.
Apply Bonferroni correction: per-test α = 0.01/10 = 0.001.

If all 10 tests pass (fail to reject H₀), conclude fairness with high
confidence.

---

## 6. Simulation Specification

### 6.1 Parameters

```haskell
simParams :: SimParams
simParams = SimParams
  { totalSlots      = 1_000_000      -- T = 10^6 slots
  , activeCoeff     = 0.20           -- f
  , numValidators   = 10             -- V
  , seeds           = [1..10]        -- 10 random seeds
  , significanceLevel = 0.01
  }
```

### 6.2 Stake Distributions

Three distributions are tested:

**Uniform:** σ_j = 1/V for all j.

```haskell
uniformStake :: Int -> [Rational]
uniformStake v = replicate v (1 % v)
```

**Zipf:** σ_j ∝ 1/j (heavy-tailed, models real stake distributions).

```haskell
zipfStake :: Int -> [Rational]
zipfStake v = let raw = [1 % j | j <- [1..v]]
                  total = sum raw
              in map (/ total) raw
```

**Power-law:** σ_j ∝ j^{-2} (even heavier tail).

```haskell
powerLawStake :: Int -> [Rational]
powerLawStake v = let raw = [1 % (j*j) | j <- [1..v]]
                      total = sum raw
                  in map (/ total) raw
```

### 6.3 Simulation Loop

```haskell
simulate :: SimParams -> StakeDistribution -> Seed -> ChiSquaredResult
simulate params stakes seed =
  let nonce0 = sha256 (encode seed)
      counts = accumArray (+) 0 (1, numValidators params)
        [ (j, 1)
        | s <- [0 .. totalSlots params - 1]
        , j <- [1 .. numValidators params]
        , let vrfOut = vrfEval (secretKey j) (nonce0 <> encode s)
        , let sigma  = fromRational (stakes !! (j-1)) :: Double
        , let thresh = 1 - exp(sigma * log(1 - activeCoeff params))  -- Double arithmetic
        , vrfNormalize vrfOut < thresh
        ]
      expected = [ fromIntegral (totalSlots params) * pj
                 | sigma_r <- stakes
                 , let sigma = fromRational sigma_r :: Double
                 , let pj = 1 - exp(sigma * log(1 - activeCoeff params))
                 ]
      chiSq = sum [ (fromIntegral (counts ! j) - expected !! (j-1))^2
                    / (expected !! (j-1))
                  | j <- [1 .. numValidators params]
                  ]
      df = numValidators params
      pValue = 1 - chiSquaredCDF df chiSq
  in ChiSquaredResult chiSq df pValue (pValue >= significanceLevel params)
```

---

## 7. Power Analysis

### 7.1 Detecting Deviation

For a deviation of magnitude δ (e.g., one validator gets (1+δ) times
their expected share), the power of the chi-squared test is:

```
Power = Pr[reject H₀ | H₁ true with deviation δ]
```

The non-centrality parameter (for a single cell's deviation):

```
λ_nc = T · p_j · δ²
```

For T = 10^6 and a 5% deviation (δ = 0.05) with p_j ≈ 0.022
(uniform stakes, 10 validators, p_j = 1 - 0.80^{0.1} ≈ 0.02209):

```
λ_nc = 10^6 · 0.022 · 0.0025 ≈ 55
```

With df = 10 and α = 0.01, the critical value is χ²_{0.99, 10} ≈ 23.21.
The power is:

```
Power = Pr[χ² > 23.21 | λ_nc = 55] > 0.99
```

The test has >99% power to detect a 5% deviation at T = 10^6.

### 7.2 Minimum Detectable Deviation

For 80% power (conventional threshold) with df = 10, we use the
non-central chi-squared distribution directly.  The required
non-centrality parameter λ_nc satisfies:

```
Pr[χ²(df=10, λ_nc) > χ²_{0.99, 10}] = 0.80
```

where χ²_{0.99, 10} ≈ 23.21.  Numerically, λ_nc ≈ 29.3.

```
δ_min = sqrt(λ_nc / (T · p_j))
      ≈ sqrt(29.3 / (10^6 · 0.022))
      ≈ sqrt(1.33 · 10^{-3})
      ≈ 3.65%
```

The test can reliably detect deviations as small as ~3.7% from expected
proportionality at T = 10^6 slots.

---

## 8. Formal Fairness Bound

**Theorem 8.1 (Concentration Bound).**

By the Chernoff bound, for any validator j and any ε > 0:

```
Pr[|count_j - E[count_j]| > ε · E[count_j]] ≤ 2 · exp(-ε² · E[count_j] / 3)
```

For T = 10^6, p_j ≈ 0.022 (uniform stakes, 10 validators):

```
E[count_j] = 10^6 · 0.022 = 22,000
```

For ε = 0.05 (5% deviation):

```
Pr[|count_j - 22000| > 1100] ≤ 2 · exp(-0.0025 · 22000 / 3)
                               = 2 · exp(-18.33)
                               ≈ 2.2 · 10^{-8}
```

Over V = 10 validators (union bound):

```
Pr[any validator deviates by >5%] ≤ 10 · 2.2 · 10^{-8} = 2.2 · 10^{-7}
```

With 10^6 slots, all validators stay within 5% of their expected share
with probability > 99.99998%.  □

---

## 9. Summary

| Property | Result | Method |
|----------|--------|--------|
| VRF uniformity | Computationally uniform in [0,1) | DDH reduction (§2) |
| Slot independence | Computationally independent across slots | ROM + Elligator2 (§3) |
| Expected proportionality | E[count_j] = T·p_j, linear in σ_j | Binomial analysis (§4) |
| Chi-squared test | α=0.01, 10 seeds, Bonferroni corrected | Standard statistical test (§5) |
| Power at T=10^6 | >99% for 5% deviation; detects ≥3.7% at 80% power | Non-centrality analysis (§7) |
| Concentration | <2.2×10^{-7} prob of >5% deviation for any validator | Chernoff bound (§8) |
