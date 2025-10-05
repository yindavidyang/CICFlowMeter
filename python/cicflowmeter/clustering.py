"""CSV ingestion, dimensionality reduction, and clustering utilities.

This module mirrors the responsibilities of the legacy Java Weka glue layer
(`WekaFactory` + `WekaXMeans`). It intentionally keeps a small dependency
surface by relying on ``numpy`` for the linear algebra involved in PCA and
implementing a lightweight k-means loop with a BIC-like score to emulate
X-Means' model selection between ``k_min`` and ``k_max`` clusters.
"""

from __future__ import annotations

import csv
import logging
import math
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

import numpy as np

from .summary_statistics import SummaryStatistics

logger = logging.getLogger(__name__)

MISSING_VALUES = {"", "?", "na", "n/a", "null", "none"}


# ---------------------------------------------------------------------------
# Dataset ingestion helpers
# ---------------------------------------------------------------------------


def load_flow_csv(path: Path | str) -> "FlowDataset":
    """Load a flow CSV, keeping string columns for later lookups.

    The Java implementation removes rows containing missing values but keeps
    all columns so the UI can still group by categorical attributes. Numeric
    projections are computed on a copy with string columns removed; the Python
    port follows the same strategy.
    """

    return _load_dataset(Path(path), drop_nominal=False)


def load_url_csv(path: Path | str) -> "FlowDataset":
    """Load a URL CSV and drop nominal columns up front.

    ``ClusterWorker`` in the Java code uses this variant before clustering URL
    statistics. The flow is the same as ``load_flow_csv`` except that string
    columns are discarded entirely.
    """

    return _load_dataset(Path(path), drop_nominal=True)


@dataclass(frozen=True)
class FlowDataset:
    """Container wrapping the raw records alongside numeric projections."""

    columns: Tuple[str, ...]
    rows: Tuple[Mapping[str, str], ...]
    numeric_columns: Tuple[str, ...]
    numeric_matrix: np.ndarray

    def has_numeric_data(self) -> bool:
        return self.numeric_matrix.size > 0 and self.numeric_matrix.shape[0] > 0

    def numeric_view(self) -> np.ndarray:
        return self.numeric_matrix


def dataset_from_matrix(matrix: np.ndarray, column_names: Sequence[str]) -> FlowDataset:
    """Construct a :class:`FlowDataset` from an in-memory numeric matrix."""

    if matrix.ndim != 2:
        raise ValueError("matrix must be two-dimensional")
    if len(column_names) != matrix.shape[1]:
        raise ValueError("column_names length must match matrix width")

    rows: List[Mapping[str, str]] = []
    for row in matrix:
        rows.append({name: _stringify(value) for name, value in zip(column_names, row)})

    return FlowDataset(
        columns=tuple(column_names),
        rows=tuple(rows),
        numeric_columns=tuple(column_names),
        numeric_matrix=matrix.astype(float, copy=False),
    )


def _load_dataset(path: Path, drop_nominal: bool) -> FlowDataset:
    if not path.exists():
        raise FileNotFoundError(path)

    rows: List[MutableMapping[str, str]] = []
    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"CSV {path} is missing a header row")
        columns = tuple(reader.fieldnames)

        for row_index, row in enumerate(reader):
            if row is None:
                continue

            cleaned: Dict[str, str] = {}
            skip_row = False
            for column in columns:
                value_raw = row.get(column, "")
                value = value_raw.strip() if value_raw is not None else ""
                if _is_missing(value):
                    skip_row = True
                    break
                cleaned[column] = value

            if skip_row:
                logger.debug("Dropping row %d from %s due to missing values", row_index, path)
                continue
            rows.append(cleaned)

    numeric_columns, numeric_matrix = _extract_numeric_columns(rows, drop_nominal)
    dataset = FlowDataset(
        columns=columns,
        rows=tuple(rows),
        numeric_columns=numeric_columns,
        numeric_matrix=numeric_matrix,
    )
    logger.debug(
        "Loaded dataset %s: %d rows, %d numeric columns",
        path,
        numeric_matrix.shape[0],
        numeric_matrix.shape[1] if numeric_columns else 0,
    )
    return dataset


def _extract_numeric_columns(
    rows: Sequence[Mapping[str, str]],
    drop_nominal: bool,
) -> Tuple[Tuple[str, ...], np.ndarray]:
    if not rows:
        return tuple(), np.zeros((0, 0), dtype=float)

    columns = list(rows[0].keys())
    numeric_columns: List[str] = []
    numeric_data: List[List[float]] = []

    for column in columns:
        column_values = [row[column] for row in rows]
        if all(_is_float(value) for value in column_values):
            numeric_columns.append(column)
        elif drop_nominal:
            # URL datasets drop nominal columns entirely.
            continue

    if not numeric_columns:
        return tuple(), np.zeros((len(rows), 0), dtype=float)

    for row in rows:
        numeric_data.append([float(row[col]) for col in numeric_columns])

    matrix = np.asarray(numeric_data, dtype=float)
    return tuple(numeric_columns), matrix


def _is_missing(value: str) -> bool:
    return value.lower() in MISSING_VALUES


def _is_float(value: str) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def _stringify(value: float) -> str:
    return f"{float(value)}"


# ---------------------------------------------------------------------------
# Dimensionality reduction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Projection:
    points: np.ndarray
    explained_variance_ratio: Tuple[float, ...]


def perform_pca(matrix: np.ndarray, n_components: int = 2) -> Projection:
    """Return a 2-D PCA projection and explained variance percentages."""

    if matrix.size == 0:
        return Projection(points=np.zeros((0, n_components)), explained_variance_ratio=(0.0,) * n_components)

    n_components = min(n_components, matrix.shape[1])
    if n_components == 0:
        return Projection(points=np.zeros((matrix.shape[0], 0)), explained_variance_ratio=tuple())

    centered = matrix - matrix.mean(axis=0, keepdims=True)
    # ``full_matrices=False`` yields compact SVD suitable for PCA.
    u, s, vh = np.linalg.svd(centered, full_matrices=False)
    components = vh[:n_components]
    transformed = np.dot(centered, components.T)

    variances = (s ** 2) / (matrix.shape[0] - 1 if matrix.shape[0] > 1 else 1)
    total_variance = variances.sum()
    if total_variance <= 0:
        explained = np.zeros(n_components)
    else:
        explained = variances[:n_components] / total_variance

    return Projection(points=transformed, explained_variance_ratio=tuple(float(val) for val in explained))


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClusterResult:
    """Clustering output for a particular feature space."""

    labels: Tuple[int, ...]
    centroids: np.ndarray
    inertia: float
    projection: np.ndarray

    def k(self) -> int:
        return len(self.centroids)

    def clusters(self) -> List[np.ndarray]:
        return [self.projection[np.asarray(self.labels) == index] for index in range(self.k())]


class FlowClusterer:
    """Rudimentary X-Means analogue operating on :class:`FlowDataset`."""

    def __init__(
        self,
        dataset: FlowDataset,
        *,
        k_min: int = 3,
        k_max: int = 6,
        random_seed: int = 10,
    ) -> None:
        if dataset is None:
            raise ValueError("dataset cannot be None")
        self.dataset = dataset
        self.k_min = max(1, k_min)
        self.k_max = max(self.k_min, k_max)
        self.random_seed = random_seed
        self._raw_result: Optional[ClusterResult] = None
        self._reduced_projection: Optional[Projection] = None
        self._reduced_result: Optional[ClusterResult] = None
        self._stats: Dict[str, SummaryStatistics] = {}
        self._build_summary_statistics()

    # ------------------------------------------------------------------
    def build(self) -> None:
        self._raw_result = self._cluster(self.dataset.numeric_matrix)
        projection = perform_pca(self.dataset.numeric_matrix)
        self._reduced_projection = projection
        self._reduced_result = self._cluster(projection.points)

    def build_raw(self) -> None:
        self._raw_result = self._cluster(self.dataset.numeric_matrix)

    def build_with_dimensionality_reduction(self) -> None:
        projection = perform_pca(self.dataset.numeric_matrix)
        self._reduced_projection = projection
        self._reduced_result = self._cluster(projection.points)

    # ------------------------------------------------------------------
    def raw_result(self) -> Optional[ClusterResult]:
        return self._raw_result

    def reduced_result(self) -> Optional[ClusterResult]:
        return self._reduced_result

    def reduced_projection(self) -> Optional[Projection]:
        return self._reduced_projection

    # ------------------------------------------------------------------
    def mean_of(self, column: str) -> float:
        stats = self._stats.get(column)
        if stats is None:
            logger.info("Column %s is not numeric or absent", column)
            return 0.0
        return stats.getMean()

    def group_by(self, column: str) -> Dict[str, Tuple[int, ...]]:
        if column not in self.dataset.columns:
            logger.info("Column %s not present in dataset", column)
            return {}

        use_numeric = column in self.dataset.numeric_columns
        rows = self.dataset.rows
        labels: Dict[str, List[int]] = {}
        for index, row in enumerate(rows):
            value = row[column] if not use_numeric else f"{float(row[column]):g}"
            labels.setdefault(value, []).append(index)
        return {key: tuple(value) for key, value in labels.items()}

    # ------------------------------------------------------------------
    def _build_summary_statistics(self) -> None:
        if not self.dataset.numeric_columns:
            return

        for column_index, column_name in enumerate(self.dataset.numeric_columns):
            stats = SummaryStatistics()
            column_values = self.dataset.numeric_matrix[:, column_index]
            for value in column_values:
                stats.add_value(float(value))
            self._stats[column_name] = stats

    def _cluster(self, matrix: np.ndarray) -> Optional[ClusterResult]:
        if matrix.size == 0:
            return None

        n_samples = matrix.shape[0]
        n_features = matrix.shape[1]
        if n_samples == 0 or n_features == 0:
            return None

        best_result: Optional[ClusterResult] = None
        best_score = math.inf
        upper = min(self.k_max, n_samples)
        lower = max(1, min(self.k_min, upper))
        for k in range(lower, upper + 1):
            labels, centroids, inertia = _kmeans(matrix, k, self.random_seed)
            score = _bic_like_score(inertia, n_samples, n_features, k)
            if score < best_score:
                best_score = score
                best_result = ClusterResult(
                    labels=tuple(int(label) for label in labels),
                    centroids=centroids,
                    inertia=float(inertia),
                    projection=matrix,
                )
        return best_result


# ---------------------------------------------------------------------------
# Lightweight k-means + scoring helpers
# ---------------------------------------------------------------------------


def _kmeans(matrix: np.ndarray, k: int, seed: int) -> Tuple[np.ndarray, np.ndarray, float]:
    rng = random.Random(seed)
    n_samples, _ = matrix.shape
    k = max(1, min(k, n_samples))

    # Initialise centroids by sampling distinct rows.
    if k == n_samples:
        initial_indices = list(range(n_samples))
    else:
        initial_indices = rng.sample(range(n_samples), k)
    centroids = matrix[initial_indices].copy()

    for _ in range(50):
        # Compute squared distances to centroids.
        distances = np.sum((matrix[:, np.newaxis, :] - centroids[np.newaxis, :, :]) ** 2, axis=2)
        labels = np.argmin(distances, axis=1)

        new_centroids = centroids.copy()
        for idx in range(k):
            members = matrix[labels == idx]
            if len(members) == 0:
                new_centroids[idx] = matrix[rng.randrange(n_samples)]
            else:
                new_centroids[idx] = members.mean(axis=0)

        if np.allclose(new_centroids, centroids, atol=1e-4):
            centroids = new_centroids
            break
        centroids = new_centroids

    distances = np.sum((matrix - centroids[labels]) ** 2, axis=1)
    inertia = float(np.sum(distances))
    return labels, centroids, inertia


def _bic_like_score(
    inertia: float,
    n_samples: int,
    n_features: int,
    k: int,
) -> float:
    if n_samples <= k or n_features == 0:
        return inertia

    variance = inertia / (n_samples - k) / n_features
    variance = max(variance, 1e-9)
    log_likelihood = -0.5 * n_samples * n_features * math.log(2 * math.pi * variance) - 0.5 * (n_samples - k) * n_features
    num_parameters = k * (n_features + 1)
    bic = -2 * log_likelihood + num_parameters * math.log(n_samples)
    return bic


__all__ = [
    "FlowDataset",
    "FlowClusterer",
    "ClusterResult",
    "Projection",
    "dataset_from_matrix",
    "load_flow_csv",
    "load_url_csv",
    "perform_pca",
]
