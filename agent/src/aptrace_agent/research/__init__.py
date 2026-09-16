"""
Generic autonomous firmware research for APTrace.

APTrace owns:
- safe deterministic execution
- evidence collection and provenance
- deduplication and budgets
- argument validation
- structural lead generation and resolution

The research model owns:
- choosing which direction matters next
- choosing among discovered leads
- proposing claims and hypotheses
- identifying contradictions and open questions
- deciding when sufficient evidence exists

Structural firmware arguments such as addresses, pin-table indexes,
and function identities should normally be resolved through
APTrace-generated leads rather than manufactured by the model.
"""
