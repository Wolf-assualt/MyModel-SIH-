"""Pure NumPy statistical metrics for distribution shift, divergence testing, and statistical distance."""
import numpy as np


def compute_ks_distance(baseline: np.ndarray, target: np.ndarray) -> float:
    """Calculate 2-sample Kolmogorov-Smirnov distance using empirical cumulative distribution functions.
    
    Returns:
        float: Max absolute difference in ECDF in range [0.0, 1.0].
    """
    u = np.asarray(baseline, dtype=np.float64).ravel()
    v = np.asarray(target, dtype=np.float64).ravel()

    if len(u) == 0 or len(v) == 0:
        return 0.0

    u_sorted = np.sort(u)
    v_sorted = np.sort(v)

    # Union of all sample coordinates as evaluation points
    pooled = np.sort(np.concatenate([u_sorted, v_sorted]))

    # Empirical CDF evaluation: F(x) = count(samples <= x) / N
    cdf_u = np.searchsorted(u_sorted, pooled, side="right") / len(u)
    cdf_v = np.searchsorted(v_sorted, pooled, side="right") / len(v)

    ks_stat = float(np.max(np.abs(cdf_u - cdf_v)))
    return max(0.0, min(1.0, ks_stat))


def compute_ks_p_value(baseline: np.ndarray, target: np.ndarray, ks_stat: float) -> float:
    """Calculate asymptotic p-value for the 2-sample Kolmogorov-Smirnov statistic.
    
    Returns:
        float: Two-sided p-value in [0.0, 1.0].
    """
    u = np.asarray(baseline, dtype=np.float64).ravel()
    v = np.asarray(target, dtype=np.float64).ravel()

    n1, n2 = len(u), len(v)
    if n1 == 0 or n2 == 0 or ks_stat <= 0.0:
        return 1.0

    en = np.sqrt(n1 * n2 / (n1 + n2))
    lam = (en + 0.12 + 0.11 / en) * ks_stat

    if lam >= 4.0:
        return 0.0
    if lam <= 0.0:
        return 1.0

    # Kolmogorov distribution series
    p = 0.0
    for j in range(1, 101):
        term = 2.0 * ((-1) ** (j - 1)) * np.exp(-2.0 * (j ** 2) * (lam ** 2))
        p += term
        if abs(term) < 1e-12:
            break

    return float(max(0.0, min(1.0, p)))


def compute_psi(baseline: np.ndarray, target: np.ndarray, bins: int = 10) -> float:
    """Calculate Population Stability Index (PSI) between baseline and target distributions.
    
    Uses epsilon smoothing (1e-4) to prevent division by zero or undefined log in unobserved bins.
    
    Returns:
        float: PSI divergence score (>= 0.0, where 0.0 indicates identical distributions).
    """
    u = np.asarray(baseline, dtype=np.float64).ravel()
    v = np.asarray(target, dtype=np.float64).ravel()

    if len(u) == 0 or len(v) == 0:
        return 0.0

    min_val = float(min(np.min(u), np.min(v)))
    max_val = float(max(np.max(u), np.max(v)))

    if min_val == max_val:
        return 0.0

    # Discretize into uniform bins across the joint domain
    bin_edges = np.linspace(min_val, max_val, bins + 1)

    b_counts, _ = np.histogram(u, bins=bin_edges)
    t_counts, _ = np.histogram(v, bins=bin_edges)

    # Epsilon-smoothed probabilities
    eps = 1e-4
    b_prob = (b_counts + eps) / (len(u) + eps * bins)
    t_prob = (t_counts + eps) / (len(v) + eps * bins)

    psi = np.sum((t_prob - b_prob) * np.log(t_prob / b_prob))
    return float(max(0.0, psi))


def wasserstein_distance_1d(u: np.ndarray, v: np.ndarray, num_quantiles: int = 100) -> float:
    """Calculate 1D Earth Mover's Distance (Wasserstein distance) using quantile sampling.
    
    Returns:
        float: Mean absolute difference between quantile functions.
    """
    arr_u = np.asarray(u, dtype=np.float64).ravel()
    arr_v = np.asarray(v, dtype=np.float64).ravel()

    if len(arr_u) == 0 or len(arr_v) == 0:
        return 0.0

    # If identical arrays
    if len(arr_u) == len(arr_v) and np.array_equal(arr_u, arr_v):
        return 0.0

    quantiles = np.linspace(0.01, 0.99, num_quantiles)
    u_quant = np.quantile(arr_u, quantiles)
    v_quant = np.quantile(arr_v, quantiles)

    return float(np.mean(np.abs(u_quant - v_quant)))


def compute_energy_distance(u: np.ndarray, v: np.ndarray) -> float:
    """Calculate 1D Statistical Energy Distance: 2*E|U - V| - E|U - U'| - E|V - V'|.
    
    Returns:
        float: Energy distance (>= 0.0, with 0.0 representing identical distributions).
    """
    arr_u = np.asarray(u, dtype=np.float64).ravel()
    arr_v = np.asarray(v, dtype=np.float64).ravel()

    if len(arr_u) == 0 or len(arr_v) == 0:
        return 0.0

    # If identical arrays
    if len(arr_u) == len(arr_v) and np.array_equal(arr_u, arr_v):
        return 0.0

    # Subsample if sample count is large for efficiency
    if len(arr_u) > 200:
        quantiles = np.linspace(0.005, 0.995, 200)
        arr_u = np.quantile(arr_u, quantiles)
    if len(arr_v) > 200:
        quantiles = np.linspace(0.005, 0.995, 200)
        arr_v = np.quantile(arr_v, quantiles)

    diff_uv = float(np.mean(np.abs(arr_u[:, None] - arr_v[None, :])))
    diff_uu = float(np.mean(np.abs(arr_u[:, None] - arr_u[None, :])))
    diff_vv = float(np.mean(np.abs(arr_v[:, None] - arr_v[None, :])))

    energy_dist = 2.0 * diff_uv - diff_uu - diff_vv
    return float(max(0.0, energy_dist))
