"""Pure NumPy statistical metrics for distribution shift and divergence testing."""
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

    quantiles = np.linspace(0.01, 0.99, num_quantiles)
    u_quant = np.quantile(arr_u, quantiles)
    v_quant = np.quantile(arr_v, quantiles)

    return float(np.mean(np.abs(u_quant - v_quant)))
