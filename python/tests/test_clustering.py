from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from cicflowmeter.clustering import (
    FlowClusterer,
    dataset_from_matrix,
    load_flow_csv,
    load_url_csv,
    perform_pca,
)


def _write_csv(path: Path) -> None:
    path.write_text(
        """flow_id,src_ip,packets,bytes,proto
F1,10.0.0.1,10,500,TCP
F2,10.0.0.2,,300,UDP
F3,10.0.0.3,20,1000,TCP
F4,10.0.0.4,15,750,UDP
F5,10.0.0.5,?,600,TCP
""",
        encoding="utf-8",
    )


def test_load_flow_csv_drops_missing_rows(tmp_path):
    csv_path = tmp_path / "flows.csv"
    _write_csv(csv_path)

    dataset = load_flow_csv(csv_path)
    assert dataset.columns == ("flow_id", "src_ip", "packets", "bytes", "proto")
    # Missing rows should be removed (only 3 valid rows remain).
    assert dataset.numeric_matrix.shape == (3, 2)
    assert dataset.numeric_columns == ("packets", "bytes")


def test_load_url_csv_removes_nominal_columns(tmp_path):
    csv_path = tmp_path / "urls.csv"
    _write_csv(csv_path)

    dataset = load_url_csv(csv_path)
    assert dataset.numeric_matrix.shape == (3, 2)
    # FlowClusterer should be able to operate on the dataset even when
    # ``drop_nominal`` is enforced.
    clusterer = FlowClusterer(dataset, k_min=2, k_max=3, random_seed=1)
    clusterer.build()
    raw = clusterer.raw_result()
    assert raw is not None
    assert len(raw.labels) == 3

    mean_packets = clusterer.mean_of("packets")
    assert mean_packets == pytest.approx(15.0)

    grouped = clusterer.group_by("proto")
    assert grouped["TCP"] == (0, 1)
    assert grouped["UDP"] == (2,)


def test_perform_pca_returns_expected_shape(tmp_path):
    csv_path = tmp_path / "flows.csv"
    _write_csv(csv_path)
    dataset = load_flow_csv(csv_path)

    projection = perform_pca(dataset.numeric_matrix)
    assert projection.points.shape == (3, 2)
    assert len(projection.explained_variance_ratio) == 2
    assert np.isclose(sum(projection.explained_variance_ratio), 1.0)


def test_dataset_from_matrix_round_trips_numpy_matrix():
    matrix = np.asarray([[1.0, 2.0], [3.0, 4.0]], dtype=float)
    dataset = dataset_from_matrix(matrix, ("a", "b"))

    assert dataset.columns == ("a", "b")
    assert dataset.numeric_columns == ("a", "b")
    np.testing.assert_array_equal(dataset.numeric_matrix, matrix)


def test_flow_clusterer_handles_small_sample_counts():
    matrix = np.asarray([[42.0, 7.0]], dtype=float)
    dataset = dataset_from_matrix(matrix, ("x", "y"))

    clusterer = FlowClusterer(dataset, k_min=3, k_max=6)
    clusterer.build_raw()

    result = clusterer.raw_result()
    assert result is not None
    assert len(result.labels) == 1
