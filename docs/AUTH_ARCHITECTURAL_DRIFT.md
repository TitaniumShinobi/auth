# Architectural drift diagnosis

The repository's earlier wizard installed `.auth-runtime`, `.auth-kit`, an AUTH-owned verifier, workflow, baseline, and lifecycle swap machinery. That implementation contradicted the corrected product boundary: AUTH must leave target-native authentication, evidence, and tests—not a persistent AUTH subsystem.

The drift occurred because durability was interpreted as persistence of AUTH artifacts. Strong provenance, journaling, atomic publication, identity-verified rollback, adversarial-replacement handling, and crash tests were then built around the wrong ownership boundary. Product proving grounds also entered reusable configuration, tests, evidence, and documentation.

The cleanup therefore preserves the safety techniques and working authentication capabilities while replacing their artifact model. It is not a rename, bulk deletion, or feature rewrite. Superseded machinery may be removed only after the target-native successor has equal or stronger coverage.
