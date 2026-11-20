# mindie-harness 0.1.6: Automatic `Stop` Route Promotion on Authorized Consent & Pre-Check `Admission` Lease Activation

[中文](harness-0.1.6.md)

`mindie-harness v0.1.6` is now available. While keeping `API_VERSION = 1` and a 100% pure-stdlib runtime (`dependencies = []`), this patch aligns `Stop` hook route promotion and `Admission` lease activation after a user enables `contribute` or `local-only` sharing on an initially read-only profile:

- **Automatic `capture_mode="disabled"` -> `"public-transcript"` Promotion on Authorized `Stop` (`runtime/knowledge_binding.py`)**: Once `_authorized_stop_scope` confirms active `contribute` or `local-only` consent and an in-scope `project_roots` workspace, `run_stop_capture` automatically promotes initial cold-start `capture_mode == "disabled"` routes to `"public-transcript"` (`force_public_transcript=True, retire_previous=True`) whenever a real host `transcript_adapter` is present.
- **Pre-Check `Admission` Lease Minting & Revocation Guard**: Authorized `Stop` invocations now evaluate `Admission` state and mint initial session leases before forwarding to `accept_stop` (permanently honoring `status == "inactive"` revocations with `stage="inert", reason="revoked"` while keeping unauthorized/disabled `Stop` calls on the `< 5ms` zero-SQLite fast path), accompanied by a rebuilt deterministic `dist/mindie-harness-seed.pyz`.
