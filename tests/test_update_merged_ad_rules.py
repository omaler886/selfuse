import io
import json
import unittest
import urllib.error
from contextlib import redirect_stderr
from http.client import IncompleteRead
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from scripts import update_merged_ad_rules as rules


WUMING_SOURCES = (
    (rules.WUMING_LITE_SOURCE, "adguard_lite.txt"),
    (rules.WUMING_HOSTS_SOURCE, "hosts_rules.txt"),
    (rules.WUMING_WHITELIST_SOURCE, "whitelist.txt"),
)


def make_response(content: bytes) -> MagicMock:
    """Return a successful HTTP response mock containing the supplied bytes."""
    response = MagicMock()
    response.status = 200
    response.read.return_value = content
    response.__enter__.return_value = response
    return response


class WumingSourceTests(unittest.TestCase):
    def test_release_urls_and_metadata(self) -> None:
        """Check all Wuming inputs use release assets without claiming a git path."""
        for source, filename in WUMING_SOURCES:
            with self.subTest(source=source.name):
                expected_url = (
                    "https://github.com/Wuming155/AdGuard-Rules"
                    f"/releases/latest/download/{filename}"
                )
                self.assertEqual(source.url, expected_url)
                self.assertIsNone(source.branch)
                self.assertIsNone(source.source_path)
                self.assertEqual(source.upstreams[0].url, expected_url)
                self.assertIsNone(source.upstreams[0].branch)
                self.assertIsNone(source.upstreams[0].path)
                self.assertIn("GitHub Releases", source.upstreams[0].note)

    def test_manifest_matches_source_metadata(self) -> None:
        """Check the published Wuming source catalog matches the build inputs."""
        manifest = json.loads(rules.MANIFEST.read_text(encoding="utf-8"))
        catalog = {source["name"]: source for source in manifest["sourceCatalog"]}
        for source, _ in WUMING_SOURCES:
            with self.subTest(source=source.name):
                self.assertEqual(catalog[source.name], rules.format_source(source))

    def test_release_formats_preserve_dns_rules(self) -> None:
        """Check release formats retain blocks and exceptions without scoped rules."""
        fixtures = (
            ("adguard-block", "! Header\n||ads.example^\n||scoped.example^$script\n"),
            ("hosts-block", "# Header\n0.0.0.0 ads.example\n192.0.2.1 safe.example\n"),
            ("adguard-allow", "! Header\n@@||ads.example^\n||blocked.example^\n"),
        )
        with TemporaryDirectory() as directory:
            source_path = Path(directory) / "source.txt"
            for kind, content in fixtures:
                with self.subTest(kind=kind):
                    source_path.write_text(content, encoding="utf-8")
                    self.assertEqual(rules.read_text_rules(source_path, kind), {"ads.example"})


class DownloadTests(unittest.TestCase):
    def setUp(self) -> None:
        """Create an isolated cache and disable retry delays for each test."""
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.target = Path(directory.name) / "raw" / "source.txt"
        self.url = rules.WUMING_LITE_URL
        self.sleep = self.enterContext(patch("time.sleep"))
        self.stderr = self.enterContext(redirect_stderr(io.StringIO()))

    def write_cache(self, content: bytes) -> None:
        """Populate this test's cache with content; return no value."""
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_bytes(content)

    def test_successful_download_refreshes_cache(self) -> None:
        """Check a successful download replaces old cache data without a retry."""
        self.write_cache(b"old rules")
        with patch.object(rules.urllib.request, "urlopen", return_value=make_response(b"new rules")):
            rules.fetch_file_with_cache(self.url, self.target)
        self.assertEqual(self.target.read_bytes(), b"new rules")
        self.sleep.assert_not_called()
        self.assertEqual(self.stderr.getvalue(), "")

    def test_missing_release_asset_fails_with_url_without_retry(self) -> None:
        """Check a cold-cache 404 fails visibly instead of dropping a rule source."""
        error = urllib.error.HTTPError(self.url, 404, "Not Found", None, None)
        with patch.object(rules.urllib.request, "urlopen", side_effect=error) as urlopen:
            with self.assertRaises(RuntimeError) as raised:
                rules.fetch_file_with_cache(self.url, self.target)
        self.assertIn(self.url, str(raised.exception))
        self.assertIn("404", str(raised.exception))
        self.assertIs(raised.exception.__cause__, error)
        self.assertFalse(self.target.exists())
        self.assertEqual(urlopen.call_count, 1)
        self.sleep.assert_not_called()

    def test_transient_errors_retry_before_succeeding(self) -> None:
        """Check transient HTTP and connection failures can recover on retry."""
        errors = (
            urllib.error.HTTPError(self.url, 429, "Too Many Requests", None, None),
            urllib.error.HTTPError(self.url, 503, "Unavailable", None, None),
            urllib.error.URLError("connection unavailable"),
            TimeoutError("timed out"),
            ConnectionResetError("connection reset"),
            IncompleteRead(b"partial", 100),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                self.sleep.reset_mock()
                responses = [error, make_response(b"complete rules")]
                with patch.object(rules.urllib.request, "urlopen", side_effect=responses) as urlopen:
                    rules.fetch_file_with_cache(self.url, self.target)
                self.assertEqual(self.target.read_bytes(), b"complete rules")
                self.assertEqual(urlopen.call_count, 2)
                self.sleep.assert_called_once_with(1)

    def test_exhausted_retries_fail_without_cache(self) -> None:
        """Check repeated network failures stop after a bounded number of attempts."""
        error = urllib.error.URLError("offline")
        with patch.object(rules.urllib.request, "urlopen", side_effect=error) as urlopen:
            with self.assertRaisesRegex(RuntimeError, "offline"):
                rules.fetch_file_with_cache(self.url, self.target)
        self.assertEqual(urlopen.call_count, rules.DOWNLOAD_ATTEMPTS)
        self.assertEqual(self.sleep.call_count, rules.DOWNLOAD_ATTEMPTS - 1)
        self.assertFalse(self.target.exists())

    def test_cached_fallback_is_visible(self) -> None:
        """Check a nonempty cache survives a missing asset and emits a warning."""
        self.write_cache(b"cached rules")
        error = urllib.error.HTTPError(self.url, 404, "Not Found", None, None)
        with patch.object(rules.urllib.request, "urlopen", side_effect=error):
            rules.fetch_file_with_cache(self.url, self.target)
        self.assertEqual(self.target.read_bytes(), b"cached rules")
        self.assertIn("WARNING", self.stderr.getvalue())
        self.assertIn(self.url, self.stderr.getvalue())
        self.assertIn(str(self.target), self.stderr.getvalue())
        self.sleep.assert_not_called()

    def test_partial_download_does_not_overwrite_cache(self) -> None:
        """Check interrupted response reads leave the last complete cache intact."""
        self.write_cache(b"cached rules")
        response = make_response(b"unused")
        response.read.side_effect = IncompleteRead(b"partial", 100)
        with patch.object(rules.urllib.request, "urlopen", return_value=response) as urlopen:
            rules.fetch_file_with_cache(self.url, self.target)
        self.assertEqual(urlopen.call_count, rules.DOWNLOAD_ATTEMPTS)
        self.assertEqual(self.target.read_bytes(), b"cached rules")
        self.assertIn("WARNING", self.stderr.getvalue())

    def test_empty_cache_is_not_a_fallback(self) -> None:
        """Check an empty cache cannot turn a failed download into a successful build."""
        self.write_cache(b"")
        error = urllib.error.HTTPError(self.url, 404, "Not Found", None, None)
        with patch.object(rules.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(RuntimeError):
                rules.fetch_file_with_cache(self.url, self.target)

    def test_empty_download_does_not_overwrite_cache(self) -> None:
        """Check an empty upstream response fails without deleting cached rules."""
        self.write_cache(b"cached rules")
        with patch.object(rules.urllib.request, "urlopen", return_value=make_response(b"")):
            with self.assertRaisesRegex(ValueError, "empty"):
                rules.fetch_file_with_cache(self.url, self.target)
        self.assertEqual(self.target.read_bytes(), b"cached rules")
        self.sleep.assert_not_called()

    def test_local_write_errors_are_not_hidden_by_cache(self) -> None:
        """Check filesystem failures propagate instead of silently using stale data."""
        self.write_cache(b"cached rules")
        with patch.object(rules, "fetch_file", side_effect=PermissionError("read-only")):
            with self.assertRaises(PermissionError):
                rules.fetch_file_with_cache(self.url, self.target)
        self.sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
