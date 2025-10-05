"""Enum describing the 85 flow features produced by CICFlowMeter."""

from __future__ import annotations

from enum import Enum, unique
from typing import List, Optional


@unique
class FlowFeature(Enum):
    fid = ("Flow ID", "FID", False, None)
    src_ip = ("Src IP", "SIP", False, None)
    src_port = ("Src Port", "SPT", True, None)
    dst_ip = ("Dst IP", "DIP", False, None)
    dst_port = ("Dst Port", "DPT", True, None)
    prot = ("Protocol", "PROT", True, None)
    tstp = ("Timestamp", "TSTP", False, None)
    fl_dur = ("Flow Duration", "DUR", True, None)
    tot_fw_pkt = ("Total Fwd Packet", "TFwP", True, None)
    tot_bw_pkt = ("Total Bwd packets", "TBwP", True, None)
    tot_l_fw_pkt = ("Total Length of Fwd Packet", "TLFwP", True, None)
    tot_l_bw_pkt = ("Total Length of Bwd Packet", "TLBwP", True, None)
    fw_pkt_l_max = ("Fwd Packet Length Max", "FwPLMA", True, None)
    fw_pkt_l_min = ("Fwd Packet Length Min", "FwPLMI", True, None)
    fw_pkt_l_avg = ("Fwd Packet Length Mean", "FwPLAG", True, None)
    fw_pkt_l_std = ("Fwd Packet Length Std", "FwPLSD", True, None)
    bw_pkt_l_max = ("Bwd Packet Length Max", "BwPLMA", True, None)
    bw_pkt_l_min = ("Bwd Packet Length Min", "BwPLMI", True, None)
    bw_pkt_l_avg = ("Bwd Packet Length Mean", "BwPLAG", True, None)
    bw_pkt_l_std = ("Bwd Packet Length Std", "BwPLSD", True, None)
    fl_byt_s = ("Flow Bytes/s", "FB/s", True, None)
    fl_pkt_s = ("Flow Packets/s", "FP/s", True, None)
    fl_iat_avg = ("Flow IAT Mean", "FLIATAG", True, None)
    fl_iat_std = ("Flow IAT Std", "FLIATSD", True, None)
    fl_iat_max = ("Flow IAT Max", "FLIATMA", True, None)
    fl_iat_min = ("Flow IAT Min", "FLIATMI", True, None)
    fw_iat_tot = ("Fwd IAT Total", "FwIATTO", True, None)
    fw_iat_avg = ("Fwd IAT Mean", "FwIATAG", True, None)
    fw_iat_std = ("Fwd IAT Std", "FwIATSD", True, None)
    fw_iat_max = ("Fwd IAT Max", "FwIATMA", True, None)
    fw_iat_min = ("Fwd IAT Min", "FwIATMI", True, None)
    bw_iat_tot = ("Bwd IAT Total", "BwIATTO", True, None)
    bw_iat_avg = ("Bwd IAT Mean", "BwIATAG", True, None)
    bw_iat_std = ("Bwd IAT Std", "BwIATSD", True, None)
    bw_iat_max = ("Bwd IAT Max", "BwIATMA", True, None)
    bw_iat_min = ("Bwd IAT Min", "BwIATMI", True, None)
    fw_psh_flag = ("Fwd PSH Flags", "FwPSH", True, None)
    bw_psh_flag = ("Bwd PSH Flags", "BwPSH", True, None)
    fw_urg_flag = ("Fwd URG Flags", "FwURG", True, None)
    bw_urg_flag = ("Bwd URG Flags", "BwURG", True, None)
    fw_hdr_len = ("Fwd Header Length", "FwHL", True, None)
    bw_hdr_len = ("Bwd Header Length", "BwHL", True, None)
    fw_pkt_s = ("Fwd Packets/s", "FwP/s", True, None)
    bw_pkt_s = ("Bwd Packets/s", "Bwp/s", True, None)
    pkt_len_min = ("Packet Length Min", "PLMI", True, None)
    pkt_len_max = ("Packet Length Max", "PLMA", True, None)
    pkt_len_avg = ("Packet Length Mean", "PLAG", True, None)
    pkt_len_std = ("Packet Length Std", "PLSD", True, None)
    pkt_len_var = ("Packet Length Variance", "PLVA", True, None)
    fin_cnt = ("FIN Flag Count", "FINCT", True, None)
    syn_cnt = ("SYN Flag Count", "SYNCT", True, None)
    rst_cnt = ("RST Flag Count", "RSTCT", True, None)
    pst_cnt = ("PSH Flag Count", "PSHCT", True, None)
    ack_cnt = ("ACK Flag Count", "ACKCT", True, None)
    urg_cnt = ("URG Flag Count", "URGCT", True, None)
    CWR_cnt = ("CWR Flag Count", "CWRCT", True, None)
    ece_cnt = ("ECE Flag Count", "ECECT", True, None)
    down_up_ratio = ("Down/Up Ratio", "D/URO", True, None)
    pkt_size_avg = ("Average Packet Size", "PSAG", True, None)
    fw_seg_avg = ("Fwd Segment Size Avg", "FwSgAG", True, None)
    bw_seg_avg = ("Bwd Segment Size Avg", "BwSgAG", True, None)
    fw_byt_blk_avg = ("Fwd Bytes/Bulk Avg", "FwB/BAG", True, None)
    fw_pkt_blk_avg = ("Fwd Packet/Bulk Avg", "FwP/BAG", True, None)
    fw_blk_rate_avg = ("Fwd Bulk Rate Avg", "FwBRAG", True, None)
    bw_byt_blk_avg = ("Bwd Bytes/Bulk Avg", "BwB/BAG", True, None)
    bw_pkt_blk_avg = ("Bwd Packet/Bulk Avg", "BwP/BAG", True, None)
    bw_blk_rate_avg = ("Bwd Bulk Rate Avg", "BwBRAG", True, None)
    subfl_fw_pkt = ("Subflow Fwd Packets", "SFFwP", True, None)
    subfl_fw_byt = ("Subflow Fwd Bytes", "SFFwB", True, None)
    subfl_bw_pkt = ("Subflow Bwd Packets", "SFBwP", True, None)
    subfl_bw_byt = ("Subflow Bwd Bytes", "SFBwB", True, None)
    fw_win_byt = ("FWD Init Win Bytes", "FwWB", True, None)
    bw_win_byt = ("Bwd Init Win Bytes", "BwWB", True, None)
    Fw_act_pkt = ("Fwd Act Data Pkts", "FwAP", True, None)
    fw_seg_min = ("Fwd Seg Size Min", "FwSgMI", True, None)
    atv_avg = ("Active Mean", "AcAG", True, None)
    atv_std = ("Active Std", "AcSD", True, None)
    atv_max = ("Active Max", "AcMA", True, None)
    atv_min = ("Active Min", "AcMI", True, None)
    idl_avg = ("Idle Mean", "IlAG", True, None)
    idl_std = ("Idle Std", "IlSD", True, None)
    idl_max = ("Idle Max", "IlMA", True, None)
    idl_min = ("Idle Min", "IlMI", True, None)
    Label = ("Label", "LBL", False, ["NeedManualLabel"])

    def __init__(self, display_name: str, abbr: str, numeric: bool, values: Optional[List[str]]) -> None:
        self.display_name = display_name
        self.abbr = abbr
        self.is_numeric = numeric
        self.values = values or []

    # ------------------------------------------------------------------
    @classmethod
    def get_header(cls) -> str:
        return ",".join(feature.display_name for feature in cls)

    @classmethod
    def get_feature_list(cls) -> List["FlowFeature"]:
        features: List[FlowFeature] = [cls.prot]
        collecting = False
        for feature in cls:
            if feature is cls.fl_dur:
                collecting = True
            if collecting:
                features.append(feature)
            if feature is cls.idl_min:
                break
        return features

    @classmethod
    def get_length_feature(cls) -> List["FlowFeature"]:
        keys = [
            cls.tot_l_fw_pkt,
            cls.tot_l_bw_pkt,
            cls.fl_byt_s,
            cls.fl_pkt_s,
            cls.fw_hdr_len,
            cls.bw_hdr_len,
            cls.fw_pkt_s,
            cls.bw_pkt_s,
            cls.pkt_size_avg,
            cls.fw_seg_avg,
            cls.bw_seg_avg,
        ]
        return keys

    @classmethod
    def feature_value_to_string(cls, feature: "FlowFeature", value: str) -> str:
        if feature is cls.prot:
            try:
                number = int(value)
            except (TypeError, ValueError):
                return value
            if number == 6:
                return "TCP"
            if number == 17:
                return "UDP"
        return value

    # Convenience accessors -------------------------------------------
    @property
    def name_str(self) -> str:
        return self.display_name

    def __str__(self) -> str:  # pragma: no cover - human readable repr
        return self.display_name


__all__ = ["FlowFeature"]
