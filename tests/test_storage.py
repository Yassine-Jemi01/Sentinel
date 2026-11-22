"""Storage regression tests."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel.storage.database import check_integrity


class IntegrityCheckTests(unittest.TestCase):
    def test_missing_database_does_not_create_data_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            data_home = Path(directory) / "xdg-data"
            with patch.dict("os.environ", {"XDG_DATA_HOME": str(data_home)}):
                self.assertEqual(check_integrity(), "missing")
            self.assertFalse(data_home.exists())


if __name__ == "__main__":
    unittest.main()
