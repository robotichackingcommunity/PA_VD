"""Upstream data sources.  Each module exposes fetch(cve_id) -> Facts | None
and parse(raw) -> Facts, where Facts is the common dict shape defined in
faultline.sources.facts."""
