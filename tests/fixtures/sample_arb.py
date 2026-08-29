"""Sample ARB HTML builders for integration tests."""

from pathlib import Path


def write_sample_arb(directory: Path) -> Path:
    """Write a minimal HTML architecture export into ``directory``."""
    source_path = directory / "sample-arb.html"
    source_path.write_text(
        """
        <html>
          <head><title>Sample Payments ARB</title></head>
          <body>
            <h1>Architecture Overview</h1>
            <p>The payment service exposes an HTTPS API and stores payment data.</p>
            <img src="payments-diagram.png" alt="Payments architecture diagram" />
          </body>
        </html>
        """,
        encoding="utf-8",
    )
    return source_path
