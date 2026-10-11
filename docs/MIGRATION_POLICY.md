# Migration policy

Compatible runtime changes use explicit UPGRADE. AUTH validates the candidate before activation, preserves the old runtime until the matching baseline is authenticated, and rolls back on supported failure boundaries.

Identity, sessions, credentials, product data, and product-owned integration are never heuristic migration inputs. REPAIR restores only authenticated AUTH-owned runtime bytes and never changes versions.

Irreversible or incompatible schema/identity migrations are unsupported. Before one can be implemented, it requires:

1. exact source and target contracts;
2. backup and restore proof;
3. dry-run validation on non-production fixtures;
4. explicit forward and rollback boundaries;
5. identity/session/data continuity checks;
6. an owner-approved irreversible-action statement.

Until all six exist, AUTH returns `EXTERNAL_ACTION_REQUIRED` for owner approval or `AUTH_DEVELOPMENT_REQUIRED` for missing migration machinery and performs no migration.
