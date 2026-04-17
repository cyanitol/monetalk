# Proof-06: Adaptive Controller Convergence

**DO-333 Requirement:** `doc/10-security.md` line 153
**Source:** `doc/20-economic-analysis.md` lines 186–258, `doc/06-economics.md` lines 138–178
**Assumptions used:** A9 (bounded growth: at most 10× per 100 cycles),
duration_ratio > 0 (cycle duration is strictly positive)

---

## Preamble

This document proves convergence, stability, and bounded-error properties
of UmbraVox's adaptive parameter controller.  The controller adjusts four
economic parameters (burn_rate, fee_floor, fee_ceiling, target_msgs) at
each cycle boundary to drive cycle duration toward the 11-day target.

---

## 1. System Model

### 1.1 Controller Definition

At each cycle boundary, for each parameter x:

```
duration_ratio = actual_cycle_slots / target_cycle_slots
raw(N)         = clamp(x(N) * duration_ratio, x_min, x_max)  (burn_rate, target_msgs)
               = clamp(x(N) / duration_ratio, x_min, x_max)  (fee_floor, fee_ceiling)
x(N+1)         = x(N) + D * (raw(N) - x(N))
```

where D = 0.50 (damping factor), and target_cycle_slots = 86,394 (11 days: 22 epochs × 3,927 slots/epoch at 11s/slot).
Note: the clamp is applied to the raw target *before* damping, not to the
final output (per `doc/06-economics.md` lines 153–162).  Since damping
interpolates between x(N) and raw(N), both of which are in [x_min, x_max],
the result x(N+1) is also in [x_min, x_max] by convexity (see Theorem 4.1).

### 1.2 Simplified Model (Without Clamp)

For the convergence analysis, we first consider the unclamped system:

```
x(N+1) = x(N) + D * (target(N) - x(N))
```

where target(N) corresponds to the clamped pre-damped value raw(N).

When the network reaches equilibrium (duration_ratio converges to 1.0),
`target(N) = x(N)` and the system is at a fixed point.

### 1.3 Error Dynamics

Define the error as deviation from equilibrium:

```
e(N) = x(N) - x_eq
```

where x_eq is the equilibrium value for the current network conditions.

After a step change to new equilibrium x_eq' at time N₀:

```
e(N₀) = x(N₀) - x_eq'

x(N₀+1) = x(N₀) + D * (x_eq' - x(N₀))
         = x(N₀) + D * (-e(N₀))
         = x(N₀) - D * e(N₀)

e(N₀+1) = x(N₀+1) - x_eq'
         = x(N₀) - D * e(N₀) - x_eq'
         = e(N₀) - D * e(N₀)
         = (1 - D) * e(N₀)
         = 0.5 * e(N₀)
```

---

## 2. Theorem: Geometric Convergence

**Theorem 2.1 (Geometric Convergence).**

For the unclamped controller with D = 0.5, assuming target(N) = x_eq' is constant for N ≥ N₀ (fixed equilibrium target):

```
|e(N + k)| = (1 - D)^k * |e(N)| = 0.5^k * |e(N)|
```

The error halves with each cycle.

### Proof

By induction on k:

**Base case (k = 0):** `|e(N)| = 0.5^0 * |e(N)| = |e(N)|`.  ✓

**Inductive step:** Assume `|e(N + k)| = 0.5^k * |e(N)|`.

```
e(N + k + 1) = (1 - D) * e(N + k) = 0.5 * e(N + k)
|e(N + k + 1)| = 0.5 * |e(N + k)| = 0.5 * 0.5^k * |e(N)| = 0.5^{k+1} * |e(N)|
```

□

**Convergence rate table:**

| Cycles after step change | Residual error |
|--------------------------|---------------|
| 1 | 50.0% |
| 2 | 25.0% |
| 3 | 12.5% |
| 5 | 3.125% |
| 7 | 0.78% |
| 10 | 0.098% |

Parameters converge to within 1% of equilibrium in 7 cycles (~77 days).
They converge to within 5% in 5 cycles (~55 days).

**Note:** This table applies to the step-response scenario (fixed equilibrium target after a one-time change). Under sustained growth (Section 5), the error does not decrease monotonically because the target shifts each cycle. See Section 5 for tracking error analysis under growth.

---

## 3. Theorem: No Overshoot or Oscillation

**Theorem 3.1 (Monotonic Convergence).**

For D ∈ (0, 1), the error e(N) preserves sign and strictly decreases in
magnitude at each step.  There is no overshoot and no oscillation.

### Proof

```
e(N+1) = (1 - D) * e(N)
```

Since D ∈ (0, 1), we have (1 - D) ∈ (0, 1).

1. **Sign preservation:** (1 - D) > 0, so sign(e(N+1)) = sign(e(N)).
   The error never crosses zero (no overshoot).

2. **Magnitude decrease:** |(1 - D)| < 1, so |e(N+1)| < |e(N)|.
   The error strictly decreases each step.

3. **No oscillation:** Since the sign never changes and the magnitude
   strictly decreases, the sequence {e(N)} is monotonically converging
   to 0 from one side.

This is a direct consequence of D = 0.5 lying in (0, 1).  The system is
a pure proportional controller with no integral or derivative terms,
eliminating the possibility of windup or oscillatory modes.  □

This result applies to the controller's response to a fixed target. Under time-varying inputs (e.g., fluctuating duration_ratio), the system trajectory may be non-monotonic due to exogenous disturbances, but the controller itself does not amplify or oscillate.

---

## 4. Theorem: BIBO Stability

**Theorem 4.1 (Bounded-Input Bounded-Output Stability).**

Regardless of the input sequence {target(N)}, all controller outputs
are bounded within the hard parameter limits:

```
x(N) ∈ [x_min, x_max]    for all N ≥ 0
```

Specifically:
- burn_rate ∈ [0.20, 0.80]
- fee_floor ∈ [5, 100]
- fee_ceiling ∈ [5000, 50000]
- target_msgs ∈ [1000, 100000000]

### Proof

The raw target is clamped before damping:

```
raw(N) = clamp(x(N) * r_or_1/r, x_min, x_max)
x(N+1) = x(N) + D * (raw(N) - x(N)) = (1-D)*x(N) + D*raw(N)
```

Since D = 0.5, x(N+1) = 0.5*x(N) + 0.5*raw(N), which is the midpoint
of x(N) and raw(N).

By the clamp: `raw(N) ∈ [x_min, x_max]`.  If `x(N) ∈ [x_min, x_max]`,
then x(N+1) is a convex combination of two values in [x_min, x_max],
so `x(N+1) ∈ [x_min, x_max]` (intervals are convex sets).

This holds regardless of the duration_ratio, including adversarial or
pathological inputs.  The inner clamp on raw(N) combined with the
convex interpolation provides an unconditional safety bound.

**Initial values** are within bounds (doc/06-economics.md lines 171–178):
- burn_rate(0) = 0.65 ∈ [0.20, 0.80] ✓
- fee_floor(0) = 10 ∈ [5, 100] ✓
- fee_ceiling(0) = 10000 ∈ [5000, 50000] ✓
- target_msgs(0) = 10000 ∈ [1000, 100000000] ✓

By induction: x(0) ∈ [x_min, x_max] and clamp preserves bounds, so
x(N) ∈ [x_min, x_max] for all N.  □

---

## 5. Theorem: Tracking Under Growth

**Theorem 5.1 (Steady-State Error Under Growth).**

Under continuous exponential growth where duration_ratio = r at every
cycle (r > 1 for growth), the steady-state tracking error is bounded.

For the bounded growth assumption A9 (at most 10× per 100 cycles),
the per-cycle growth rate is:

```
r = 10^{1/100} ≈ 1.0233
```

### Proof

Under continuous growth, the equilibrium shifts each cycle:

```
x_eq(N+1) = r * x_eq(N)
```

The controller tracks a moving target.  The analysis differs for the
two parameter types because their target functions have opposite
dependence on duration_ratio r:

**Case A: Multiply parameters (burn_rate, target_msgs).**
These use target(N) = x(N) * r.  The effective multiplier is
m_A = 1 + D*(r-1):

```
x(N+1) = x(N) * m_A = x(N) * (1 + 0.5 * (r - 1))
x_eq(N+1) = r * x_eq(N)
```

Define ρ(N) = x(N) / x_eq(N).  Then:

```
ρ(N+1) = (m_A / r) · ρ(N)
m_A / r = (1 + D*(r-1)) / r < 1  for r > 1
```

So ρ decays: the controller *undershoots* the growing target.

**Case B: Divide parameters (fee_floor, fee_ceiling).**
These use target(N) = x(N) / r.  The effective multiplier is
m_B = 1 - D*(1 - 1/r):

```
x(N+1) = x(N) * m_B = x(N) * (0.5 + 0.5/r)
x_eq(N+1) = x_eq(N) / r
```

The ratio evolves as:

```
ρ(N+1) = (m_B · r) · ρ(N) = ((r+1)/2) · ρ(N)
```

For r = 1.0233: (r+1)/2 ≈ 1.01165 > 1.  So ρ *grows*: the controller
*overshoots* above the shrinking target (fees decrease too slowly).

**Both cases are bounded by BIBO (Theorem 4.1).**  A9 bounds total
growth, not perpetual growth.  In practice, growth episodes are
transient: the network grows, then stabilises.

**Per-cycle lag (transient analysis).**  During a single growth cycle
with duration_ratio = r, both cases produce a relative lag of
approximately (r-1)/2:

```
Case A (multiply): relative lag = 1 - m_A/r = (r-1)(1-D)/r ≈ 1.14%
Case B (divide):   relative lag = m_B·r - 1 = (r-1)/2     ≈ 1.17%
```

Each growth cycle introduces ~1.1–1.2% relative lag (in opposite
directions: Case A undershoots, Case B overshoots).  Over K consecutive
growth cycles at rate r, the accumulated lag is bounded by:

```
Case A: 1 - (m_A/r)^K = 1 - 0.9886^K
Case B: (m_B·r)^K - 1 = 1.01165^K - 1
```

For K = 100 cycles (the A9 window):
- Case A: 1 - 0.9886^{100} ≈ 68% (undershoots by up to 68%)
- Case B: 1.01165^{100} - 1 ≈ 220% (theoretical unclamped overshoot)

Case B accumulates more lag than Case A under sustained worst-case
growth, because ρ grows rather than decays.  However, A9
limits *total* growth to 10×, so sustained r = 1.0233 for 100 cycles
is the absolute worst case.  **Note:** The 220% figure is the
*tracking ratio* (ρ − 1), not the actual parameter value.  The BIBO
clamp (Theorem 4.1) bounds the actual parameter to [x_min, x_max]
regardless of tracking error.  When the tracking ratio exceeds the
clamp bounds, the controller enters *clamp saturation*: the actual
parameter is pinned at the clamp limit, and the tracking error
reflects the distance between the clamp limit and the (now
unreachable) equilibrium target.  For example, fee_floor ∈ [5, 100]
MTK; if the equilibrium target drops to 3 MTK, the actual parameter
remains at 5 MTK (the clamp floor), yielding a tracking error of
5/3 − 1 ≈ 67%.  The 220% theoretical tracking error is a vacuous
upper bound because the clamp activates well before this threshold.
During clamp saturation, convergence resumes immediately once the
equilibrium target re-enters the clamped range.

**After growth stops (r → 1.0):**

The accumulated tracking error converges to 0 geometrically:

```
|e(N+k)| = 0.5^k * |e(N)|
```

Convergence to < 1% of the lag in 7 cycles; to < 0.1% in 10 cycles.
Since BIBO stability (Theorem 4.1) unconditionally bounds the parameter
within [x_min, x_max], the controller's practical tracking ability is
guaranteed even during extreme growth episodes.  □

---

## 6. Lyapunov Stability Analysis

### 6.1 Lyapunov Function

Define V: ℝ → ℝ≥0 as:

```
V(e) = e²
```

### 6.2 Theorem (Asymptotic Stability)

**Theorem 6.1.**  The equilibrium e = 0 of the unclamped controller is
asymptotically stable in the sense of Lyapunov.

### Proof

**Condition 1 (Positive definiteness):**
V(e) = e² > 0 for all e ≠ 0, and V(0) = 0.  ✓

**Condition 2 (Strict decrease along trajectories):**

```
V(e(N+1)) = e(N+1)² = ((1-D) * e(N))² = (1-D)² * e(N)² = (1-D)² * V(e(N))
```

With D = 0.5:

```
V(e(N+1)) = 0.25 * V(e(N))
```

Since 0.25 < 1: V(e(N+1)) < V(e(N)) for all e(N) ≠ 0.  ✓

**Condition 3 (Radial unboundedness):**
V(e) = e² → ∞ as |e| → ∞.  ✓

All three Lyapunov conditions are satisfied.  The equilibrium is globally
asymptotically stable.

**Rate of convergence:**  V decreases by factor 0.25 each step, so
|e| decreases by factor 0.5.  This confirms the geometric convergence
result of Theorem 2.1.  □

---

## 7. Contraction Mapping Interpretation

**Theorem 7.1.**  The controller update map T(x) = x + D * (x_eq - x) is
a contraction on ℝ with Lipschitz constant L = |1 - D| = 0.5.

### Proof

For any x₁, x₂ ∈ ℝ:

```
|T(x₁) - T(x₂)| = |(x₁ + D*(x_eq - x₁)) - (x₂ + D*(x_eq - x₂))|
                  = |(1-D)(x₁ - x₂)|
                  = |1-D| * |x₁ - x₂|
                  = 0.5 * |x₁ - x₂|
```

Since 0.5 < 1, T is a contraction.  By the Banach fixed-point theorem,
T has a unique fixed point (x_eq) and iteration converges to it from
any initial point.  □

---

## 8. Multi-Parameter Analysis

### 8.1 Independence

The four parameters (burn_rate, fee_floor, fee_ceiling, target_msgs) are
updated independently: each has its own update equation with no cross-terms.

```
burn_rate_raw    = clamp(burn_rate(N)*r,   0.20, 0.80)
burn_rate(N+1)   = burn_rate(N)   + 0.5*(burn_rate_raw   - burn_rate(N))

fee_floor_raw    = clamp(fee_floor(N)/r,   5,    100)
fee_floor(N+1)   = fee_floor(N)   + 0.5*(fee_floor_raw   - fee_floor(N))

fee_ceiling_raw  = clamp(fee_ceiling(N)/r, 5000, 50000)
fee_ceiling(N+1) = fee_ceiling(N) + 0.5*(fee_ceiling_raw  - fee_ceiling(N))

target_msgs_raw  = clamp(target_msgs(N)*r, 1000, 100000000)
target_msgs(N+1) = target_msgs(N) + 0.5*(target_msgs_raw - target_msgs(N))
```

where r = duration_ratio (shared input, but each parameter's evolution
is a scalar equation).

Note: doc/20 Section 3 uses a simplified single-case formulation (target = param * duration_ratio) for all parameters. This proof distinguishes multiply parameters (burn_rate, target_msgs: target = param * r) from divide parameters (fee_floor, fee_ceiling: target = param / r), which produce different tracking error profiles under sustained growth (§5).

**Theorem 8.1.**  Each parameter converges independently.  The
multi-parameter system's convergence rate equals the single-parameter
rate (0.5 per cycle).

All four parameters respond to the shared input signal duration_ratio, so they experience correlated disturbances. However, this shared input does not create state coupling: each parameter's convergence rate depends only on the damping factor D = 0.5, not on the other parameters' values or on the input signal. Correlated inputs cause correlated transient errors but do not affect convergence guarantees.

**Proof.**  The Jacobian of the unclamped 4-dimensional system is:

```
J = diag(1-D, 1-D, 1-D, 1-D) = 0.5 * I₄
```

All eigenvalues are 0.5 < 1.  The spectral radius ρ(J) = 0.5.  The
system converges geometrically with rate 0.5 in all four dimensions
simultaneously.  □

### 8.2 Sensitivity Analysis

From `doc/20-economic-analysis.md` lines 258–265:

| Parameter | Sensitivity to 10× growth | Response time |
|-----------|---------------------------|---------------|
| burn_rate | HIGH (primary lever) | 3–5 cycles |
| fee_floor | MEDIUM | 3–5 cycles |
| fee_ceiling | LOW | 3–5 cycles |
| target_msgs | MEDIUM | 3–5 cycles |

All parameters respond within 5 cycles (converge to ≤ 3.125% error),
consistent with the geometric convergence rate 0.5^5 = 0.03125.

### 8.3 Clamp Interaction

When a parameter hits its clamp bound, convergence may slow because the
clamp prevents the controller from reaching the unclamped equilibrium.
However, BIBO stability (Theorem 4.1) guarantees the parameter remains
within bounds.  When the equilibrium shifts back within the clamp range,
normal geometric convergence resumes.

**Worst case:** The parameter saturates at a bound and the equilibrium
is outside the bound.  The tracking error is then:

```
e_sat = |x_eq - x_bound|
```

This represents a design limit: if network conditions require a parameter
value outside [x_min, x_max], the controller cannot fully track.  The
bounds are chosen conservatively (doc/06-economics.md lines 171–178) to
cover expected operating ranges.

---

## 9. Convergence Rate Table

| Cycles | Error (% of initial) | Cumulative time |
|--------|---------------------|-----------------|
| 0 | 100.0% | 0 days |
| 1 | 50.0% | 11 days |
| 2 | 25.0% | 22 days |
| 3 | 12.5% | 33 days |
| 4 | 6.25% | 44 days |
| 5 | 3.125% | 55 days |
| 7 | 0.781% | 77 days |
| 10 | 0.098% | 110 days |

**DO-333 target:** Parameters converge within 5 cycles after a shock
(doc/16-verification-plan.md line 113).  At 5 cycles, residual error
is 3.125%, within the ±5% tolerance band.  ✓

---

## 10. Summary of Properties

| Property | Result | Method |
|----------|--------|--------|
| Geometric convergence | 0.5^k per cycle | Induction (§2) |
| No overshoot/oscillation | Monotonic approach | Sign analysis (§3) |
| BIBO stability | Hard bounds guaranteed | Clamp function (§4) |
| Tracking under growth | ~1.1–1.2% lag/cycle (multiply params undershoot, divide params overshoot); BIBO-bounded | Transient + clamp analysis (§5) |
| Lyapunov stability | Asymptotically stable (unclamped system) | V = e², decay ratio 0.25 (§6) |
| Contraction mapping | Lipschitz 0.5, unique fixed point (unclamped) | Banach theorem (§7) |
| Multi-parameter independence | All 4 params converge at rate 0.5 | Diagonal Jacobian (§8) |
