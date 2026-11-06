import unittest

try:
    from . import run_all, smoke
except ImportError:
    import run_all
    import smoke


class RunAllTests(unittest.TestCase):
    def test_profiles_do_not_conflict_internally(self) -> None:
        for profile in run_all.PROFILES.values():
            specs = run_all.build_specs("127.0.0.1", profile)
            self.assertEqual([], run_all.endpoint_conflicts(specs))

    def test_high_profile_uses_non_privileged_common_ports(self) -> None:
        profile = run_all.PROFILES["high"]
        self.assertEqual(1502, profile.modbus)
        self.assertEqual(1102, profile.siemens)
        self.assertEqual(8080, profile.ewon)

    def test_full_profile_enables_the_read_only_schneider_identity_fixture(self) -> None:
        profile = run_all.PROFILES["high"]
        spec = next(spec for spec in run_all.build_specs("127.0.0.1", profile) if spec.name == "modbus")
        self.assertIn("--identity", spec.args)
        self.assertIn("schneider", spec.args)

    def test_beckhoff_command_includes_tcp_and_udp_ports(self) -> None:
        profile = run_all.PROFILES["canonical"]
        spec = [
            spec
            for spec in run_all.build_specs("127.0.0.1", profile)
            if spec.name == "beckhoff"
        ][0]
        command = spec.command("python")
        self.assertIn("--ads-port", command)
        self.assertIn("48898", command)
        self.assertIn("--discovery-port", command)
        self.assertIn("48899", command)

    def test_smoke_cases_cover_current_simulators(self) -> None:
        names = {case.simulator for case in smoke.build_cases("127.0.0.1", run_all.PROFILES["high"])}
        self.assertEqual(
            {
                "bacnet",
                "modbus",
                "slmp",
                "beckhoff",
                "siemens",
                "ewon",
                "snmp",
                "rockwell",
                "fins",
                "iec104",
                "phoenix",
                "mqtt",
                "dnp3",
                "opcua",
            },
            names,
        )


if __name__ == "__main__":
    unittest.main()
