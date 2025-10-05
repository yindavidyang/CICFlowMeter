"""Model classes backing the flow table view."""

from __future__ import annotations

from typing import Iterable, List, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from .types import FlowSummary


class FlowTableModel(QAbstractTableModel):
    """Qt table model storing the most recent flow summaries."""

    headers = [
        "Flow ID",
        "Start Time",
        "Source",
        "Src Port",
        "Destination",
        "Dst Port",
        "Protocol",
        "Packets",
        "Bytes",
        "Duration (s)",
    ]

    def __init__(self, *, max_rows: int = 500, parent=None) -> None:
        super().__init__(parent)
        self._rows: List[FlowSummary] = []
        self._max_rows = max_rows

    # ------------------------------------------------------------------
    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802 - Qt API
        if parent.isValid():
            return 0
        return len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):  # noqa: N802 - Qt API
        if not index.isValid() or not 0 <= index.row() < len(self._rows):
            return None

        summary = self._rows[index.row()]
        column = index.column()

        if role == Qt.DisplayRole:
            if column == 0:
                return summary.flow_id
            if column == 1:
                return summary.timestamp
            if column == 2:
                return summary.src_ip
            if column == 3:
                return str(summary.src_port)
            if column == 4:
                return summary.dst_ip
            if column == 5:
                return str(summary.dst_port)
            if column == 6:
                return summary.protocol
            if column == 7:
                return str(summary.packets)
            if column == 8:
                return str(summary.bytes)
            if column == 9:
                return f"{summary.duration_s:.3f}"

        if role == Qt.TextAlignmentRole:
            if column >= 3:
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)

        return None

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.DisplayRole,
    ):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            if 0 <= section < len(self.headers):
                return self.headers[section]
        return None

    # ------------------------------------------------------------------
    def add_flow(self, summary: FlowSummary) -> None:
        """Append a flow to the model, trimming the oldest rows when needed."""
        if self._max_rows and len(self._rows) >= self._max_rows:
            self.beginRemoveRows(QModelIndex(), 0, 0)
            self._rows.pop(0)
            self.endRemoveRows()

        insert_row = len(self._rows)
        self.beginInsertRows(QModelIndex(), insert_row, insert_row)
        self._rows.append(summary)
        self.endInsertRows()

    def clear(self) -> None:
        if not self._rows:
            return
        self.beginRemoveRows(QModelIndex(), 0, len(self._rows) - 1)
        self._rows.clear()
        self.endRemoveRows()

    def total_rows(self) -> int:
        return len(self._rows)

    def row_at(self, index: int) -> Optional[FlowSummary]:
        if 0 <= index < len(self._rows):
            return self._rows[index]
        return None

    def find_rows_by_ids(self, flow_ids: Iterable[str]) -> List[int]:
        id_set = {flow_id for flow_id in flow_ids if flow_id}
        if not id_set:
            return []
        return [index for index, summary in enumerate(self._rows) if summary.flow_id in id_set]


__all__ = ["FlowTableModel"]
