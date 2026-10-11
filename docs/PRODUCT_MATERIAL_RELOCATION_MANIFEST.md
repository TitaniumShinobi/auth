# Product material relocation manifest

This manifest preserves provenance for product-specific files removed from AUTH's public default branch. It does not copy material into another repository and is not authority to publish it elsewhere. Git history remains the byte-preserving source pending each product owner's review.

| Former path | SHA-256 at removal parent | Intended owner/destination | Sensitivity disposition |
| --- | --- | --- | --- |
| `config/chatty-vvault-local.json` | `dee6f4e23874bb4aff300c54c90b6aa7df094aa707094514fb1793641b280124` | Chatty/VVAULT private integration evidence | Product-specific configuration; do not publish as a generic example. |
| `config/chatty-vvault-shared.json` | `5f49b01c5a956a042c06fb3e68e42c9dab83eb588ee9809023ff88fc7bb35218` | Chatty/VVAULT private integration evidence | Product-specific configuration; do not publish as a generic example. |
| `config/chatty.json` | `ecee30677ffccb6a80b9a7ee48a150cad6c13d4c609c635c93ead873add49bd4` | Chatty product configuration | Product-specific identifiers and origins; no secret values were required for disposition. |
| `config/grid.json` | `163e3391036debe89e71b51f097b2b3480bb86c18afe8daec61cc260fcc18234` | GRID product configuration | Product-specific identifiers, origins, and policy; no secret values were required for disposition. |
| `config/vvault.json` | `dd06e6b7a098596841e64ada64f5e4daf48e818c9d17fabca6dbc13c471fed07` | VVAULT product configuration | Product-specific identifiers and origins; no secret values were required for disposition. |
| `static/grid-legal/MANIFEST.json` | `db876a730abd52692fca8b4a3fb2c8dd96763a547c2e9ee67288a25fb46e914e` | GRID legal publication | Legal/product evidence; owner review required before relocation. |
| `static/grid-legal/legal/eeccd` | `ca4c3af5b483664cc906a99effd399d6fe5ced808630997caf2d813e75b1673c` | GRID legal publication | Legal/product evidence; owner review required before relocation. |
| `static/grid-legal/legal/privacy` | `662e95280750e8adaae1588b173d6cc0e043c23daf0e5010c61f513df653d787` | GRID legal publication | Legal/product evidence; owner review required before relocation. |
| `static/grid-legal/legal/terms` | `f95742205defafbac03e2c183d7b7f2f2b6ac5b6f315936562193bdbe7e130f5` | GRID legal publication | Legal/product evidence; owner review required before relocation. |

The removals are narrow default-branch cleanup. They do not delete Git history, alter an owning repository, or assert that historical material is safe for public reuse.
