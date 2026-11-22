import os
import sqlite3
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from sentinel.core.models import Event
from sentinel.core.explainer import explain
from sentinel.core.correlation import correlate
import sentinel.storage.database as database
from sentinel.storage.database import (
    save_events, recent_history, managed_connection
)
from sentinel.system.distro import system_info
from sentinel.system.health import snapshot

class CoreTests(unittest.TestCase):
    def test_journal_event_conversion(self):
        event = Event.from_journal({"__REALTIME_TIMESTAMP": "0", "PRIORITY": "4", "MESSAGE": "warning", "_SYSTEMD_UNIT": "sshd.service"})
        self.assertEqual(event.priority, 4)
        self.assertEqual(event.unit, "sshd.service")
        self.assertEqual(event.source, "journald")
    def test_invalid_priority_defaults_to_info(self):
        self.assertEqual(Event.from_journal({"PRIORITY": "bad"}).priority, 6)
    def test_null_byte_is_replaced(self):
        self.assertNotIn("\x00", Event.from_journal({"MESSAGE": "abc\x00def"}).message)
    def test_ssh_failure_has_explanation(self):
        finding = explain(Event("2026-01-01T00:00:00+00:00", "Failed password for root"))
        self.assertEqual(finding.rule_id, "ssh_failed_password")
        self.assertEqual(finding.category, "Authentication")
    def test_unknown_event_is_not_called_an_attack(self):
        finding = explain(Event("2026-01-01T00:00:00+00:00", "routine service message"))
        self.assertEqual(finding.rule_id, "generic")
        self.assertEqual(finding.confidence, "low")
    def test_english_only_explanations(self):
        event = Event("2026-01-01T00:00:00+00:00", "Failed password")
        finding = explain(event)

        self.assertEqual(finding.title, "Failed SSH sign-in")
        self.assertEqual(finding.category, "Authentication")
        self.assertEqual(finding.rule_id, "ssh_failed_password")
        self.assertTrue(finding.title.isascii())
        self.assertTrue(finding.summary.isascii())

    def test_correlation_counts_repeated_events(self):
        items = [explain(Event(f"2026-01-01T00:00:0{i}+00:00", "Failed password")) for i in range(5)]
        result = correlate(items, 300)
        self.assertTrue(all(x.correlated_count == 5 for x in result))
        self.assertTrue(all(x.severity == "high" for x in result))
    def test_desktop_environment_coverage(self):
        cases = {
            "GNOME": ("gnome-shell", "gnome_desktop"),
            "KDE Plasma": ("plasmashell", "kde_plasma_desktop"),
            "Xfce": ("xfce4-panel", "xfce_desktop"),
            "Cinnamon": ("cinnamon", "cinnamon_desktop"),
            "MATE": ("mate-panel", "mate_desktop"),
            "LXQt": ("lxqt-panel", "lxqt_desktop"),
            "LXDE": ("lxsession", "lxde_desktop"),
            "Budgie": ("budgie-desktop", "budgie_desktop"),
            "COSMIC": ("cosmic-comp", "cosmic_desktop"),
        }

        for name, (identifier, expected_rule) in cases.items():
            with self.subTest(desktop=name):
                event = Event(
                    "2026-01-01T00:00:00+00:00",
                    "Component initialized",
                    identifier=identifier,
                )
                finding = explain(event)
                self.assertEqual(finding.rule_id, expected_rule)
                self.assertEqual(finding.category, "Desktop")

    def test_window_manager_coverage(self):
        cases = {
            "Openbox": ("openbox", "openbox_wm"),
            "i3": ("i3", "i3_wm"),
            "Sway": ("sway", "sway_compositor"),
            "Hyprland": ("Hyprland", "hyprland_compositor"),
            "bspwm": ("bspwm", "bspwm_wm"),
            "AwesomeWM": ("awesome", "awesome_wm"),
            "dwm": ("dwm", "dwm_wm"),
            "River": ("river", "river_compositor"),
            "Wayfire": ("wayfire", "wayfire_compositor"),
            "Labwc": ("labwc", "labwc_compositor"),
        }

        for name, (identifier, expected_rule) in cases.items():
            with self.subTest(window_manager=name):
                event = Event(
                    "2026-01-01T00:00:00+00:00",
                    "Component initialized",
                    identifier=identifier,
                )
                finding = explain(event)
                self.assertEqual(finding.rule_id, expected_rule)
                self.assertEqual(finding.category, "Desktop")

    def test_display_manager_coverage(self):
        cases = {
            "GDM": "gdm",
            "SDDM": "sddm",
            "LightDM": "lightdm",
            "LXDM": "lxdm",
            "greetd": "greetd",
        }

        for name, identifier in cases.items():
            with self.subTest(display_manager=name):
                event = Event(
                    "2026-01-01T00:00:00+00:00",
                    "Session initialized",
                    identifier=identifier,
                )
                finding = explain(event)
                self.assertEqual(finding.rule_id, "display_manager")

    def test_graphics_system_coverage(self):
        cases = {
            "Wayland": ("wayland", "wayland_graphics"),
            "Xorg": ("Xorg", "xorg_graphics"),
            "Xwayland": ("Xwayland", "xorg_graphics"),
        }

        for name, (identifier, expected_rule) in cases.items():
            with self.subTest(graphics_system=name):
                event = Event(
                    "2026-01-01T00:00:00+00:00",
                    "Display initialized",
                    identifier=identifier,
                )
                finding = explain(event)
                self.assertEqual(finding.rule_id, expected_rule)

    def test_desktop_service_coverage(self):
        cases = {
            "Desktop portal": ("xdg-desktop-portal", "desktop_portal"),
            "Notifications": ("dunst", "desktop_notifications"),
            "D-Bus": ("dbus-daemon", "desktop_dbus"),
        }

        for name, (identifier, expected_rule) in cases.items():
            with self.subTest(service=name):
                event = Event(
                    "2026-01-01T00:00:00+00:00",
                    "Service initialized",
                    identifier=identifier,
                )
                finding = explain(event)
                self.assertEqual(finding.rule_id, expected_rule)

    def test_desktop_widget_diagnostic(self):
        event = Event(
            "2026-01-01T00:00:00+00:00",
            "[desktop-widgets] _checkFullscreen: hasFullscreen=false, "
            "animationsPaused=false, windowCount=6",
        )
        finding = explain(event)

        self.assertEqual(finding.rule_id, "desktop_widget_diagnostic")
        self.assertEqual(finding.category, "Desktop")
        self.assertEqual(finding.severity, "info")

    def test_security_rules_take_precedence_over_desktop_rules(self):
        cases = [
            ("gnome-shell: Failed password for root", "ssh_failed_password"),
            ("plasmashell: AVC: denied operation", "selinux_denial"),
        ]

        for message, expected_rule in cases:
            with self.subTest(message=message):
                finding = explain(
                    Event("2026-01-01T00:00:00+00:00", message)
                )
                self.assertEqual(finding.rule_id, expected_rule)

    def test_desktop_false_positive_protection(self):
        messages = [
            "The build includes i3 support",
            "The documentation mentions dwm",
            "The word gdm appears in this report",
            "This is a windowedwm test message",
        ]

        for message in messages:
            with self.subTest(message=message):
                finding = explain(
                    Event("2026-01-01T00:00:00+00:00", message)
                )
                self.assertEqual(finding.rule_id, "generic")

    def test_desktop_component_matching(self):
        cases = [
            ("i3", "i3_wm"),
            ("dwm", "dwm_wm"),
            ("gdm", "display_manager"),
            ("gnome-shell.service", "gnome_desktop"),
        ]

        for identifier, expected_rule in cases:
            with self.subTest(identifier=identifier):
                finding = explain(
                    Event(
                        "2026-01-01T00:00:00+00:00",
                        "Component initialized",
                        identifier=identifier,
                    )
                )
                self.assertEqual(finding.rule_id, expected_rule)

    def test_desktop_errors_keep_their_real_classification(self):
        event = Event(
            "2026-01-01T00:00:00+00:00",
            "segfault at 00000000",
            priority=3,
            identifier="gnome-shell",
        )
        finding = explain(event)

        self.assertEqual(finding.rule_id, "segfault")
        self.assertEqual(finding.category, "Kernel / Process")
        self.assertEqual(finding.severity, "medium")

    def test_desktop_priority_is_not_downgraded(self):
        event = Event(
            "2026-01-01T00:00:00+00:00",
            "Renderer initialization failed",
            priority=3,
            identifier="gnome-shell",
        )
        finding = explain(event)

        self.assertEqual(finding.rule_id, "gnome_desktop")
        self.assertEqual(finding.severity, "high")

    def test_desktop_warning_keeps_warning_severity(self):
        event = Event(
            "2026-01-01T00:00:00+00:00",
            "Configuration warning",
            priority=4,
            identifier="kwin",
        )
        finding = explain(event)

        self.assertEqual(finding.rule_id, "kde_plasma_desktop")
        self.assertEqual(finding.severity, "medium")

    def test_security_detection_precedes_desktop_detection(self):
        event = Event(
            "2026-01-01T00:00:00+00:00",
            "AVC: denied { read }",
            identifier="gnome-shell",
        )
        finding = explain(event)

        self.assertEqual(finding.rule_id, "selinux_denial")

    def test_database_connection_closes_after_success(self):
        db = sqlite3.connect(":memory:")

        with patch("sentinel.storage.database.connect", return_value=db):
            with managed_connection() as connection:
                connection.execute("CREATE TABLE sample (id INTEGER)")

        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute("SELECT 1")

    def test_database_connection_closes_after_exception(self):
        db = sqlite3.connect(":memory:")

        with patch("sentinel.storage.database.connect", return_value=db):
            with self.assertRaises(RuntimeError):
                with managed_connection() as connection:
                    connection.execute("CREATE TABLE sample (id INTEGER)")
                    raise RuntimeError("Simulated database failure")

        with self.assertRaises(sqlite3.ProgrammingError):
            db.execute("SELECT 1")

    def test_sqlite_rolls_back_partial_event_batch(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {"XDG_DATA_HOME": temp}):
                db = database.connect()

                db.execute("""
                    CREATE TRIGGER reject_test_event
                    BEFORE INSERT ON events
                    WHEN NEW.message = 'force failure'
                    BEGIN
                        SELECT RAISE(ABORT, 'simulated failure');
                    END;
                """)
                db.commit()

                with patch(
                    "sentinel.storage.database.connect",
                    return_value=db,
                ):
                    with self.assertRaises(sqlite3.IntegrityError):
                        save_events([
                            Event("2026-01-01T00:00:00+00:00", "valid event"),
                            Event("2026-01-01T00:00:01+00:00", "force failure"),
                        ])

                self.assertEqual(recent_history(), [])

    def test_database_integrity_check_is_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "events.sqlite3"

            with patch(
                "sentinel.storage.database.database_path",
                return_value=db_path,
            ):
                db = database.connect()
                db.close()

                self.assertEqual(database.check_integrity(), "ok")

    def test_database_integrity_check_missing_file(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "missing.sqlite3"

            with patch(
                "sentinel.storage.database.database_path",
                return_value=db_path,
            ):
                self.assertEqual(database.check_integrity(), "missing")
                self.assertFalse(db_path.exists())

    def test_database_integrity_check_preserves_corrupt_file(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "events.sqlite3"
            original = b"This is not a SQLite database."
            db_path.write_bytes(original)

            with patch(
                "sentinel.storage.database.database_path",
                return_value=db_path,
            ):
                self.assertEqual(database.check_integrity(), "corrupt")

            self.assertEqual(db_path.read_bytes(), original)

    def test_health_snapshot_shape(self):
        self.assertIn("memory_percent", snapshot())
    def test_system_info_shape(self):
        self.assertIn("distro_name", system_info())
    def test_sqlite_deduplicates_events(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"XDG_DATA_HOME": temp}):
            event = Event("2026-01-01T00:00:00+00:00", "sample")
            self.assertEqual(save_events([event, event]), 1)
            self.assertEqual(len(recent_history()), 1)

if __name__ == "__main__":
    unittest.main()
