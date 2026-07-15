"""
Deferred profile: authorized binary / EDR research (Day Shift shape).

Not a VDH class-matrix clone. Requires RE tool backends (BN/Ghidra MCP later).
Ethics: authorized research only; no default public rule dumps.
"""

from __future__ import annotations


class BinaryReProfile:
    name = "binary_re"
    allow_exec = False  # analysis tools, not host shell by default

    def allowed_tools(self) -> list[str]:
        """
        TODO (later):
          - strings / file inventory tools
          - MCP bridges to decompiler
          - write_evidence for decrypted artifacts
          - submit_candidate for recovered rules/models with confidence
        """
        raise NotImplementedError("TODO: BinaryReProfile.allowed_tools — deferred")

    def require_authorization_flag(self, cfg: dict) -> None:
        """
        TODO:
          - require cfg or CLI --i-am-authorized-for-binary-re
          - raise ConfigError otherwise
        """
        raise NotImplementedError("TODO: require_authorization_flag")
