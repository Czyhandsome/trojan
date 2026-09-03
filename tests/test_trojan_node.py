import argparse
import http.server
import io
import importlib.machinery
import importlib.util
import json
import os
import pathlib
import shlex
import stat
import subprocess
import tempfile
import threading
import tarfile
import unittest
import urllib.parse
from unittest import mock
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1]
CLI_PATH = ROOT / "bin" / "trojan-node"
LOADER = importlib.machinery.SourceFileLoader("trojan_node", str(CLI_PATH))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
trojan_node = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(trojan_node)


class CommandSurfaceTests(unittest.TestCase):
    def parse(self, *argv):
        return trojan_node.build_parser().parse_args(list(argv))

    def test_locked_command_surface_parses(self):
        cases = [
            ("credentials", "status", "--node", "aiyun"),
            ("credentials", "rotate", "--node", "aiyun2"),
            ("cloudflare", "zones"),
            ("cloudflare", "dns", "list", "--node", "aiyun"),
            ("cloudflare", "dns", "ensure", "--node", "aiyun2"),
            ("cloudflare", "token", "list", "--node", "aiyun"),
            ("cloudflare", "token", "rotate-dns", "--node", "aiyun2"),
            ("cloudflare", "token", "revoke", "--node", "aiyun"),
            ("host", "check", "--node", "aiyun"),
            ("node", "list"),
            ("node", "show", "aiyun"),
            (
                "node", "add", "aiyun3", "--ssh-target", "aiyun3",
                "--domain", "introspect3.czyhandsome.ink",
            ),
            ("preflight", "--node", "aiyun2"),
            ("deploy", "--node", "aiyun2"),
            ("deploy", "--node", "aiyun2", "--rotate-secrets", "--apply"),
            ("verify", "--node", "aiyun"),
            ("clash", "render", "--output", "/tmp/personal-nodes.yaml"),
        ]
        for argv in cases:
            with self.subTest(argv=argv):
                self.assertIsInstance(self.parse(*argv), argparse.Namespace)

    def test_parser_accepts_declared_node_names_dynamically(self):
        parsed = self.parse("host", "check", "--node", "aiyun3")
        self.assertEqual(parsed.node, "aiyun3")


class ManifestTests(unittest.TestCase):
    def test_bundled_manifest_keeps_legacy_nodes_and_no_secret_values(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        self.assertEqual(set(manifest.nodes), {"aiyun", "aiyun2"})
        self.assertEqual(manifest.nodes["aiyun"].address, "23.95.133.118")
        self.assertEqual(manifest.nodes["aiyun2"].address, "69.33.3.215")
        text = (ROOT / "config" / "nodes.json").read_text()
        for forbidden in ("password", "tokenValue", "apiToken", "privateKey"):
            self.assertNotIn(forbidden, text)

    def test_example_manifest_is_parseable(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.example.json")
        self.assertEqual(set(manifest.nodes), {"example-node"})

    def test_manifest_uses_declared_known_hosts_aliases_without_fingerprints(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        self.assertEqual(manifest.nodes["aiyun"].ssh_host_alias, "aiyun")
        self.assertEqual(manifest.nodes["aiyun2"].ssh_host_alias, "aiyun2")
        self.assertNotIn("fingerprint", (ROOT / "config" / "nodes.json").read_text())

    def test_manifest_accepts_an_additional_valid_node(self):
        raw = json.loads((ROOT / "config" / "nodes.json").read_text())
        raw["nodes"]["aiyun3"] = {
            "address": "203.0.113.30",
            "domain": "introspect3.czyhandsome.ink",
            "sshUser": "root",
            "sshPort": 2222,
            "sshTarget": "aiyun3",
            "sshHostKey": {
                "algorithm": "ssh-ed25519",
                "knownHostsAlias": "aiyun3",
            },
            "credential": "trojan-aiyun3",
            "cloudflareTokenName": "trojan-aiyun3-dns01",
            "sourceCidr": "203.0.113.30/32",
        }
        with mock.patch.object(
            pathlib.Path, "read_text", return_value=json.dumps(raw)
        ):
            manifest = trojan_node.load_manifest(pathlib.Path("nodes.json"))
        self.assertEqual(set(manifest.nodes), {"aiyun", "aiyun2", "aiyun3"})
        self.assertEqual(manifest.nodes["aiyun3"].ssh_target, "aiyun3")

    def test_default_loader_prefers_local_inventory_and_falls_back_to_bundled(self):
        bundled_raw = json.loads((ROOT / "config" / "nodes.json").read_text())
        local_raw = json.loads(json.dumps(bundled_raw))
        local_raw["nodes"]["aiyun"]["domain"] = "local.czyhandsome.ink"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            bundled = root / "bundled.json"
            local = root / "config" / "nodes.json"
            bundled.write_text(json.dumps(bundled_raw))

            fallback = trojan_node.load_manifest(
                local_path=local, bundled_path=bundled
            )
            self.assertEqual(
                fallback.nodes["aiyun"].domain,
                bundled_raw["nodes"]["aiyun"]["domain"],
            )

            local.parent.mkdir()
            local.write_text(json.dumps(local_raw))
            local.chmod(0o600)
            preferred = trojan_node.load_manifest(
                local_path=local, bundled_path=bundled
            )
            self.assertEqual(
                preferred.nodes["aiyun"].domain, "local.czyhandsome.ink"
            )

    def test_manifest_rejects_duplicate_node_identity_fields(self):
        raw = json.loads((ROOT / "config" / "nodes.json").read_text())
        raw["nodes"]["aiyun2"]["domain"] = raw["nodes"]["aiyun"]["domain"]
        with self.assertRaisesRegex(trojan_node.SafetyError, "unique"):
            trojan_node.parse_manifest(raw)

    def test_local_inventory_with_unsafe_permissions_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            local = pathlib.Path(temp_dir) / "nodes.json"
            local.write_text((ROOT / "config" / "nodes.json").read_text())
            local.chmod(0o644)
            with self.assertRaisesRegex(trojan_node.SafetyError, "0600"):
                trojan_node.load_manifest(
                    local_path=local,
                    bundled_path=ROOT / "config" / "nodes.json",
                )


class ClashProfileSpecTests(unittest.TestCase):
    def test_bundled_profile_resolves_managed_and_client_only_nodes(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        profile = trojan_node.load_clash_profile_spec(
            ROOT / "config" / "clash-profile.json", manifest
        )

        self.assertEqual(profile.name, "Personal Nodes")
        self.assertEqual(profile.group, "节点选择")
        self.assertEqual(profile.default_node, "Aiyun1")
        self.assertTrue(profile.include_direct)
        self.assertEqual(
            [node.name for node in profile.nodes],
            ["Aiyun1", "Aiyun2", "Solo-green"],
        )
        self.assertEqual(profile.nodes[0].server, manifest.nodes["aiyun"].domain)
        self.assertEqual(profile.nodes[1].credential, "trojan-aiyun2")
        self.assertEqual(profile.nodes[2].credential, "trojan-solo-green")

    def profile_raw(self):
        return json.loads((ROOT / "config" / "clash-profile.json").read_text())

    def test_profile_rejects_unknown_managed_node(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        raw = self.profile_raw()
        raw["nodes"][0]["managedNode"] = "unknown"
        with self.assertRaisesRegex(trojan_node.SafetyError, "unknown managed node"):
            trojan_node.parse_clash_profile_spec(raw, manifest)

    def test_profile_rejects_duplicate_node_name(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        raw = self.profile_raw()
        raw["nodes"][1]["name"] = "Aiyun1"
        with self.assertRaisesRegex(trojan_node.SafetyError, "unique"):
            trojan_node.parse_clash_profile_spec(raw, manifest)

    def test_profile_rejects_missing_or_nonleading_default_node(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        for default_node, expected in (("missing", "configured"), ("Aiyun2", "first")):
            raw = self.profile_raw()
            raw["defaultNode"] = default_node
            with self.subTest(default_node=default_node):
                with self.assertRaisesRegex(trojan_node.SafetyError, expected):
                    trojan_node.parse_clash_profile_spec(raw, manifest)

    def test_profile_sources_contain_no_password_values(self):
        for path in (
            ROOT / "config" / "clash-profile.json",
            ROOT / "config" / "clash-profile.yaml.tpl",
        ):
            text = path.read_text()
            self.assertNotIn("password:", text)
            self.assertNotIn("<<secret:", text)


class ClashProfileRenderTests(unittest.TestCase):
    def setUp(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        self.profile = trojan_node.load_clash_profile_spec(
            ROOT / "config" / "clash-profile.json", manifest
        )
        self.passwords = {
            "trojan-aiyun": "first-secret",
            "trojan-aiyun2": "second-secret",
            "trojan-solo-green": "third-secret",
        }

    def test_rendered_profile_has_ordered_nodes_direct_rules_and_strict_tls(self):
        template = (ROOT / "config" / "clash-profile.yaml.tpl").read_text()
        rendered = trojan_node.render_clash_profile(
            self.profile, self.passwords, template
        )

        positions = [rendered.index(f'name: "{name}"') for name in (
            "Aiyun1", "Aiyun2", "Solo-green",
        )]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('      - "DIRECT"', rendered)
        self.assertEqual(rendered.count("skip-cert-verify: false"), 3)
        self.assertEqual(rendered.count("type: trojan"), 3)
        self.assertIn("- MATCH,节点选择", rendered)
        self.assertEqual(rendered.count("@trojan-node:"), 0)

    def test_credential_placeholders_request_only_three_passwords(self):
        placeholders = trojan_node.clash_credential_placeholders(self.profile)
        self.assertEqual(set(placeholders), {
            "Aiyun1", "Aiyun2", "Solo-green",
        })
        self.assertEqual(
            placeholders["Solo-green"],
            "<<secret:generic/trojan-solo-green/password>>",
        )
        encoded = json.dumps(placeholders)
        self.assertNotIn("cloudflare", encoded.lower())
        self.assertNotIn("token", encoded.lower())

    def test_render_rejects_missing_or_duplicate_template_markers(self):
        template = (ROOT / "config" / "clash-profile.yaml.tpl").read_text()
        with self.assertRaisesRegex(trojan_node.SafetyError, "marker"):
            trojan_node.render_clash_profile(
                self.profile,
                self.passwords,
                template.replace("  # @trojan-node:proxies\n", ""),
            )
        with self.assertRaisesRegex(trojan_node.SafetyError, "marker"):
            trojan_node.render_clash_profile(
                self.profile,
                self.passwords,
                template + "  # @trojan-node:proxies\n",
            )

    def test_validated_output_is_0600_and_refuses_an_existing_target(self):
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp_dir:
            output = pathlib.Path(temp_dir) / "personal-nodes.yaml"
            with mock.patch.object(
                trojan_node.shutil, "which", return_value="/usr/local/bin/mihomo"
            ):
                trojan_node.write_validated_clash_profile(
                    self.profile,
                    self.passwords,
                    output,
                    template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                    runner=lambda *_args, **_kwargs: completed,
                )
                self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                self.assertIn('name: "Aiyun1"', output.read_text())
                with self.assertRaisesRegex(trojan_node.SafetyError, "exists"):
                    trojan_node.write_validated_clash_profile(
                        self.profile,
                        self.passwords,
                        output,
                        template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                        runner=lambda *_args, **_kwargs: completed,
                    )
                link = pathlib.Path(temp_dir) / "linked.yaml"
                link.symlink_to(output)
                with self.assertRaisesRegex(trojan_node.SafetyError, "exists"):
                    trojan_node.write_validated_clash_profile(
                        self.profile,
                        self.passwords,
                        link,
                        template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                        runner=lambda *_args, **_kwargs: completed,
                    )

    def test_validation_failure_removes_output_and_redacts_subprocess_text(self):
        secret = self.passwords["trojan-aiyun"]
        completed = subprocess.CompletedProcess(
            [], 1, stdout=secret, stderr=f"invalid {secret}"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            output = pathlib.Path(temp_dir) / "personal-nodes.yaml"
            with mock.patch.object(
                trojan_node.shutil, "which", return_value="/usr/local/bin/mihomo"
            ):
                with self.assertRaises(trojan_node.SafetyError) as caught:
                    trojan_node.write_validated_clash_profile(
                        self.profile,
                        self.passwords,
                        output,
                        template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                        runner=lambda *_args, **_kwargs: completed,
                    )
            self.assertFalse(output.exists())
            self.assertNotIn(secret, str(caught.exception))

    def test_atomic_install_race_preserves_the_concurrent_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = pathlib.Path(temp_dir) / "personal-nodes.yaml"

            def runner(_argv, **_kwargs):
                output.write_text("concurrent owner\n")
                return subprocess.CompletedProcess([], 0, stdout="", stderr="")

            with mock.patch.object(
                trojan_node.shutil, "which", return_value="/usr/local/bin/mihomo"
            ):
                with self.assertRaisesRegex(trojan_node.SafetyError, "exists"):
                    trojan_node.write_validated_clash_profile(
                        self.profile,
                        self.passwords,
                        output,
                        template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                        runner=runner,
                    )

            self.assertEqual(output.read_text(), "concurrent owner\n")

    def test_mihomo_validation_uses_existing_home_and_bounded_timeout(self):
        observed = {}
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as temp_dir:
            home = pathlib.Path(temp_dir) / "clash-home"
            home.mkdir()
            output = pathlib.Path(temp_dir) / "personal-nodes.yaml"

            def runner(argv, **kwargs):
                observed["argv"] = argv
                observed["timeout"] = kwargs["timeout"]
                return completed

            with mock.patch.object(
                trojan_node.shutil, "which", return_value="/usr/local/bin/mihomo"
            ):
                trojan_node.write_validated_clash_profile(
                    self.profile,
                    self.passwords,
                    output,
                    template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                    mihomo_home=home,
                    runner=runner,
                )

        self.assertEqual(observed["argv"][1:3], ["-t", "-d"])
        self.assertEqual(observed["argv"][3], str(home))
        self.assertEqual(observed["timeout"], 30)

    def test_mihomo_timeout_cleans_temporary_output(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = pathlib.Path(temp_dir) / "personal-nodes.yaml"
            with mock.patch.object(
                trojan_node.shutil, "which", return_value="/usr/local/bin/mihomo"
            ):
                with self.assertRaisesRegex(trojan_node.SafetyError, "timed out"):
                    trojan_node.write_validated_clash_profile(
                        self.profile,
                        self.passwords,
                        output,
                        template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                        mihomo_home=pathlib.Path(temp_dir),
                        runner=mock.Mock(side_effect=subprocess.TimeoutExpired([], 30)),
                    )
            self.assertFalse(output.exists())
            self.assertEqual(list(pathlib.Path(temp_dir).glob(".*.tmp")), [])

    def test_clash_context_wraps_only_configured_password_placeholders(self):
        observed = {}

        def runner(argv, **kwargs):
            observed["argv"] = argv
            observed["env"] = kwargs["env"]
            config_index = argv.index("--from") + 1
            observed["config"] = json.loads(
                pathlib.Path(argv[config_index]).read_text()
            )
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

        result = trojan_node.run_in_clash_credential_context(
            self.profile,
            ["clash", "render", "--output", "/tmp/personal-nodes.yaml"],
            runner=runner,
            environ={"CREDS_SHOULD_NOT_LEAK": "bad", "PATH": "/usr/bin"},
        )

        self.assertEqual(result, 0)
        self.assertEqual(observed["config"], {
            "Aiyun1": "<<secret:generic/trojan-aiyun/password>>",
            "Aiyun2": "<<secret:generic/trojan-aiyun2/password>>",
            "Solo-green": "<<secret:generic/trojan-solo-green/password>>",
        })
        self.assertNotIn("CREDS_SHOULD_NOT_LEAK", observed["env"])
        self.assertEqual(observed["env"][trojan_node.CREDS_CONTEXT_ENV], "1")
        self.assertIn("--profile", observed["argv"])
        self.assertIn("personal", observed["argv"])

    def test_main_renders_metadata_without_secret_values(self):
        environment = {
            trojan_node.CREDS_CONTEXT_ENV: "1",
            trojan_node.credential_env_key("trojan-aiyun", "password"): "first-secret",
            trojan_node.credential_env_key("trojan-aiyun2", "password"): "second-secret",
            trojan_node.credential_env_key("trojan-solo-green", "password"): "third-secret",
        }
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            target = pathlib.Path(temp_dir) / "personal-nodes.yaml"
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                trojan_node, "write_validated_clash_profile", return_value=target
            ), mock.patch("sys.stdout", output):
                result = trojan_node.main([
                    "clash", "render", "--output", str(target)
                ])

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["profile"], "Personal Nodes")
        self.assertEqual(payload["nodes"], ["Aiyun1", "Aiyun2", "Solo-green"])
        for secret in self.passwords.values():
            self.assertNotIn(secret, output.getvalue())

    def test_main_redacts_sensitive_mihomo_stdout_and_stderr(self):
        environment = {
            trojan_node.CREDS_CONTEXT_ENV: "1",
            trojan_node.credential_env_key("trojan-aiyun", "password"): "first-secret",
            trojan_node.credential_env_key("trojan-aiyun2", "password"): "second-secret",
            trojan_node.credential_env_key("trojan-solo-green", "password"): "third-secret",
        }
        sensitive_diagnostic = "first-secret second-secret third-secret"
        completed = subprocess.CompletedProcess(
            [], 1, stdout=sensitive_diagnostic, stderr=sensitive_diagnostic
        )
        original_write = trojan_node.write_validated_clash_profile
        stdout = io.StringIO()
        stderr = io.StringIO()

        with tempfile.TemporaryDirectory() as temp_dir:
            target = pathlib.Path(temp_dir) / "personal-nodes.yaml"

            def fail_validation(profile, passwords, output):
                return original_write(
                    profile,
                    passwords,
                    output,
                    template_path=ROOT / "config" / "clash-profile.yaml.tpl",
                    mihomo_home=pathlib.Path(temp_dir),
                    runner=lambda *_args, **_kwargs: completed,
                )

            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                trojan_node.shutil, "which", return_value="/usr/local/bin/mihomo"
            ), mock.patch.object(
                trojan_node, "write_validated_clash_profile", side_effect=fail_validation
            ), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                result = trojan_node.main([
                    "clash", "render", "--output", str(target)
                ])

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("failed Mihomo validation", stderr.getvalue())
        for secret in self.passwords.values():
            self.assertNotIn(secret, stderr.getvalue())


class NodeRegistrationTests(unittest.TestCase):
    def test_registered_ssh_target_rejects_user_port_or_address_drift(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        node = manifest.nodes["aiyun"]
        resolved = subprocess.CompletedProcess(
            [], 0,
            "hostname 8.8.8.8\nuser deploy\nport 2202\nhostkeyalias aiyun\n",
            "",
        )
        with self.assertRaisesRegex(trojan_node.SafetyError, "changed"):
            trojan_node.validate_registered_ssh_target(
                node, runner=lambda *_args, **_kwargs: resolved
            )

    def test_ssh_target_rejects_shell_syntax_and_requires_public_ip(self):
        for target in ("aiyun3; uname", "-oProxyCommand=bad", "aiyun3 extra"):
            with self.subTest(target=target):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.resolve_ssh_target(target)

        completed = subprocess.CompletedProcess(
            [], 0, "hostname node.example.test\nuser deploy\nport 2202\n", ""
        )
        with self.assertRaisesRegex(trojan_node.SafetyError, "explicit public"):
            trojan_node.resolve_ssh_target(
                "deploy@node.example.test", runner=lambda *_args, **_kwargs: completed
            )
        resolved = trojan_node.resolve_ssh_target(
            "deploy@node.example.test",
            public_ip="8.8.4.4",
            runner=lambda *_args, **_kwargs: completed,
        )
        self.assertEqual((resolved["user"], resolved["port"]), ("deploy", 2202))
        self.assertEqual(resolved["hostAlias"], "[node.example.test]:2202")

    def test_local_inventory_refuses_symlink_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            real = root / "real.json"
            real.write_text("{}")
            link = root / "nodes.json"
            link.symlink_to(real)
            with self.assertRaisesRegex(trojan_node.SafetyError, "regular file"):
                trojan_node.write_local_manifest({"schemaVersion": 1}, link)

    def test_add_resolves_ssh_validates_trust_and_writes_local_inventory(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            if argv[:2] == ["ssh", "-G"]:
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    stdout=(
                        "host aiyun3\n"
                        "hostname 8.8.4.4\n"
                        "user root\n"
                        "port 2222\n"
                        "hostkeyalias aiyun3\n"
                    ),
                    stderr="",
                )
            if argv[0] == "ssh-keygen":
                return subprocess.CompletedProcess(
                    argv, 0, stdout="aiyun3 ssh-ed25519 a2V5\n", stderr=""
                )
            if argv[0] == "ssh":
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = pathlib.Path(temp_dir)
            local = root / "config" / "nodes.json"
            args = trojan_node.build_parser().parse_args([
                "node", "add", "aiyun3",
                "--ssh-target", "aiyun3",
                "--domain", "introspect3.czyhandsome.ink",
            ])
            node = trojan_node.register_node(
                args,
                reader=lambda _prompt: "aiyun3",
                runner=runner,
                local_path=local,
                bundled_path=ROOT / "config" / "nodes.json",
            )
            self.assertEqual(node.name, "aiyun3")
            self.assertEqual(node.address, "8.8.4.4")
            self.assertEqual(node.ssh_user, "root")
            self.assertEqual(node.ssh_port, 2222)
            self.assertEqual(node.ssh_target, "aiyun3")
            self.assertEqual(node.credential, "trojan-aiyun3")
            self.assertEqual(node.cloudflare_token_name, "trojan-aiyun3-dns01")
            self.assertEqual(stat.S_IMODE(local.stat().st_mode), 0o600)
            raw = json.loads(local.read_text())
            self.assertEqual(raw["nodes"]["aiyun3"]["sourceCidr"], "8.8.4.4/32")
            self.assertNotIn("password", local.read_text())
            self.assertTrue(any(call[:2] == ["ssh", "-G"] for call in calls))
            self.assertTrue(any(call[0] == "ssh-keygen" for call in calls))


class ProgressTests(unittest.TestCase):
    def test_long_action_emits_secret_safe_heartbeats(self):
        output = io.StringIO()
        reporter = trojan_node.ProgressReporter(stream=output)
        release = threading.Event()
        timer = threading.Timer(0.04, release.set)
        timer.start()
        try:
            result = trojan_node.run_with_heartbeat(
                reporter,
                6,
                "install-1",
                lambda: release.wait() or "done",
                interval_seconds=0.01,
            )
        finally:
            timer.cancel()
        self.assertTrue(result)
        text = output.getvalue()
        self.assertIn("install-1", text)
        self.assertIn("running", text)
        self.assertIn("elapsed=", text)
        self.assertNotIn("password", text)


class CredsAdapterTests(unittest.TestCase):
    def setUp(self):
        self.manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        self.node = self.manifest.nodes["aiyun"]

    def test_status_uses_presence_only_json_contract(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(
                argv,
                0,
                stdout=(
                    '{"schemaVersion":1,"credential":{"type":"generic",'
                    '"name":"trojan-aiyun"},"fields":['
                    '{"name":"password","status":"PRESENT"},'
                    '{"name":"cloudflare-token","status":"MISSING"}]}'
                ),
                stderr="",
            )

        result = trojan_node.credentials_status(self.manifest, self.node, runner=runner)
        self.assertEqual(result, {
            "password": "PRESENT", "cloudflare-token": "MISSING"
        })
        argv, kwargs = calls[0]
        self.assertEqual(argv, [
            "creds", "show", "generic", "trojan-aiyun",
            "--fields", "password", "cloudflare-token",
            "--profile", "personal", "--format", "json",
        ])
        self.assertTrue(kwargs["capture_output"])

    def test_status_rejects_malformed_or_error_state(self):
        cases = [
            subprocess.CompletedProcess([], 1, stdout="{}", stderr="raw diagnostic"),
            subprocess.CompletedProcess([], 0, stdout="not-json", stderr=""),
            subprocess.CompletedProcess(
                [], 0,
                stdout=(
                    '{"schemaVersion":1,"fields":['
                    '{"name":"password","status":"ERROR"}]}'
                ),
                stderr="",
            ),
        ]
        for completed in cases:
            with self.subTest(completed=completed):
                with self.assertRaises(trojan_node.SafetyError) as caught:
                    trojan_node.credentials_status(
                        self.manifest, self.node, runner=lambda *_a, **_kw: completed
                    )
                self.assertNotIn("raw diagnostic", str(caught.exception))

    def test_store_secret_uses_stdin_and_never_argv_or_output(self):
        calls = []
        secret = "test-only-high-entropy-secret"

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="Updated", stderr="")

        trojan_node.store_credential_field(
            self.manifest, self.node, "password", secret, runner=runner
        )
        argv, kwargs = calls[0]
        self.assertNotIn(secret, " ".join(argv))
        self.assertEqual(kwargs["input"], secret + "\n")
        self.assertTrue(kwargs["capture_output"])

    def test_store_failure_is_sanitized(self):
        secret = "test-only-high-entropy-secret"
        completed = subprocess.CompletedProcess(
            [], 1, stdout=secret, stderr="helper failure " + secret
        )
        with self.assertRaises(trojan_node.SafetyError) as caught:
            trojan_node.store_credential_field(
                self.manifest,
                self.node,
                "cloudflare-token",
                secret,
                runner=lambda *_a, **_kw: completed,
            )
        self.assertNotIn(secret, str(caught.exception))

    def test_credential_context_reexec_generates_and_cleans_node_placeholder(self):
        raw = json.loads((ROOT / "config" / "nodes.json").read_text())
        raw["nodes"]["aiyun3"] = {
            "address": "8.8.4.4",
            "domain": "introspect3.czyhandsome.ink",
            "sshUser": "root",
            "sshPort": 22,
            "sshTarget": "aiyun3",
            "sshHostKey": {
                "algorithm": "ssh-ed25519",
                "knownHostsAlias": "aiyun3",
            },
            "credential": "trojan-aiyun3",
            "cloudflareTokenName": "trojan-aiyun3-dns01",
            "sourceCidr": "8.8.4.4/32",
        }
        manifest = trojan_node.parse_manifest(raw)
        args = trojan_node.build_parser().parse_args([
            "deploy", "--node", "aiyun3", "--apply",
        ])
        calls = []
        temporary_path = None

        def runner(argv, **kwargs):
            nonlocal temporary_path
            calls.append((argv, kwargs))
            from_paths = [
                pathlib.Path(argv[index + 1])
                for index, item in enumerate(argv) if item == "--from"
            ]
            temporary_path = from_paths[1]
            self.assertTrue(temporary_path.is_file())
            self.assertEqual(stat.S_IMODE(temporary_path.stat().st_mode), 0o600)
            placeholder = temporary_path.read_text()
            self.assertIn("<<secret:generic/trojan-aiyun3/password>>", placeholder)
            self.assertIn(
                "<<secret:generic/trojan-aiyun3/cloudflare-token>>", placeholder
            )
            self.assertNotIn("token-manager-value", placeholder)
            return subprocess.CompletedProcess(argv, 0)

        rc = trojan_node.run_in_credential_context(
            manifest,
            args,
            ["deploy", "--node", "aiyun3", "--apply"],
            runner=runner,
            environ={"PATH": os.environ.get("PATH", "")},
        )
        self.assertEqual(rc, 0)
        argv, kwargs = calls[0]
        self.assertEqual(argv[:2], ["creds", "exec"])
        from_paths = [argv[index + 1] for index, item in enumerate(argv) if item == "--from"]
        self.assertEqual(from_paths, [
            str(ROOT / "config" / "credentials-manager.json"),
            str(temporary_path),
        ])
        self.assertFalse(temporary_path.exists())
        self.assertEqual(kwargs["env"][trojan_node.CREDS_CONTEXT_ENV], "1")
        combined = " ".join(argv) + json.dumps(kwargs["env"])
        self.assertNotIn("token-manager-value", combined)

    def test_only_manager_placeholder_is_repository_tracked(self):
        manager = (ROOT / "config" / "credentials-manager.json").read_text()
        self.assertIn("<<secret:generic/cloudflare-czyhandsome/token-manager>>", manager)
        self.assertFalse((ROOT / "config" / "credentials-aiyun.json").exists())
        self.assertFalse((ROOT / "config" / "credentials-aiyun2.json").exists())

    def test_secret_bundle_is_consumed_from_environment(self):
        manager_key = trojan_node.credential_env_key(
            "cloudflare-czyhandsome", "token-manager"
        )
        password_key = trojan_node.credential_env_key("trojan-aiyun", "password")
        node_token_key = trojan_node.credential_env_key(
            "trojan-aiyun", "cloudflare-token"
        )
        environ = {
            manager_key: "manager-value",
            password_key: "password-value",
            node_token_key: "node-token-value",
            "PATH": "/bin",
        }
        bundle = trojan_node.consume_secret_bundle(
            self.manifest, self.node, require_manager=True, require_node=True,
            environ=environ,
        )
        self.assertEqual(bundle.manager_token, "manager-value")
        self.assertEqual(bundle.password, "password-value")
        self.assertEqual(bundle.node_token, "node-token-value")
        self.assertEqual(environ, {"PATH": "/bin"})

    def test_missing_required_secret_fails_without_naming_value(self):
        with self.assertRaises(trojan_node.SafetyError):
            trojan_node.consume_secret_bundle(
                self.manifest, self.node, require_manager=True,
                require_node=False, environ={},
            )


class CloudflareApiTests(unittest.TestCase):
    def test_paginated_get_uses_bearer_and_collects_all_pages(self):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlsplit(self.path)
                query = urllib.parse.parse_qs(parsed.query)
                requests.append((parsed.path, query, self.headers.get("Authorization")))
                page = int(query.get("page", ["1"])[0])
                payload = {
                    "success": True,
                    "result": [{"id": f"zone-{page}", "name": f"z{page}.test"}],
                    "result_info": {
                        "page": page, "per_page": 1, "count": 1, "total_count": 2
                    },
                    "errors": [],
                    "messages": [],
                }
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = trojan_node.CloudflareClient(
                "manager-test-token",
                base_url=f"http://127.0.0.1:{server.server_port}/client/v4",
            )
            result = client.list_paginated("/zones", {"name": "example.test"})
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertEqual([item["id"] for item in result], ["zone-1", "zone-2"])
        self.assertEqual([call[1]["page"] for call in requests], [["1"], ["2"]])
        self.assertTrue(all(call[2] == "Bearer manager-test-token" for call in requests))

    def test_api_failure_does_not_expose_token_or_response_detail(self):
        secret = "manager-test-token"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps({
                    "success": False,
                    "errors": [{"message": "upstream detail " + secret}],
                    "result": None,
                }).encode()
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            client = trojan_node.CloudflareClient(
                secret, base_url=f"http://127.0.0.1:{server.server_port}/client/v4"
            )
            with self.assertRaises(trojan_node.SafetyError) as caught:
                client.request("GET", "/zones")
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn("upstream detail", str(caught.exception))

    def test_zone_resolution_and_record_lookup_are_exact(self):
        calls = []

        class Client:
            def list_paginated(self, path, query=None):
                calls.append((path, query))
                if path == "/zones":
                    return [{"id": "zone-1", "name": "czyhandsome.ink", "status": "active"}]
                return [{"id": "record-1", "type": "A", "name": "introspect.czyhandsome.ink"}]

        zone = trojan_node.resolve_unique_zone(Client(), "czyhandsome.ink")
        records = trojan_node.list_node_dns_records(
            Client(), zone["id"], "introspect.czyhandsome.ink"
        )
        self.assertEqual(zone["id"], "zone-1")
        self.assertEqual(records[0]["id"], "record-1")
        self.assertEqual(calls, [
            ("/zones", {"name": "czyhandsome.ink"}),
            ("/zones/zone-1/dns_records", {"name": "introspect.czyhandsome.ink"}),
        ])

    def test_zone_resolution_rejects_zero_multiple_or_inactive(self):
        cases = [
            [],
            [{"id": "a", "name": "czyhandsome.ink"}, {"id": "b", "name": "czyhandsome.ink"}],
            [{"id": "a", "name": "czyhandsome.ink", "status": "pending"}],
        ]
        for zones in cases:
            with self.subTest(zones=zones):
                class Client:
                    def list_paginated(self, *_args, **_kwargs):
                        return zones
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.resolve_unique_zone(Client(), "czyhandsome.ink")

    def test_manager_token_warns_only_within_thirty_days(self):
        now = datetime(2026, 8, 31, tzinfo=timezone.utc)
        self.assertIsNotNone(trojan_node.manager_token_expiry_warning(
            {"expires_on": "2026-09-15T00:00:00Z"}, now=now
        ))
        self.assertIsNone(trojan_node.manager_token_expiry_warning(
            {"expires_on": "2027-02-27T00:00:00Z"}, now=now
        ))
        self.assertIsNone(trojan_node.manager_token_expiry_warning({}, now=now))

    def test_manager_expiry_metadata_falls_back_to_verified_token_id(self):
        class Client:
            def request(self, method, path):
                self.assertion = (method, path)
                return {"id": "manager-id", "status": "active"}

            def list_tokens(self):
                return [
                    {"id": "other", "expires_on": "2026-09-01T00:00:00Z"},
                    {"id": "manager-id", "expires_on": "2027-02-27T00:00:00Z"},
                ]

        metadata = trojan_node.manager_token_metadata(Client())
        self.assertEqual(metadata["id"], "manager-id")
        self.assertEqual(metadata["expires_on"], "2027-02-27T00:00:00Z")


class CloudflareDnsTests(unittest.TestCase):
    def setUp(self):
        self.node = trojan_node.load_manifest(
            ROOT / "config" / "nodes.json"
        ).nodes["aiyun"]

    def test_dns_plan_noop_create_and_update(self):
        self.assertEqual(trojan_node.plan_dns_change([], self.node)["action"], "create")
        current = [{
            "id": "record-1", "type": "A", "name": self.node.domain,
            "content": self.node.address, "ttl": 1, "proxied": False,
        }]
        self.assertEqual(trojan_node.plan_dns_change(current, self.node)["action"], "noop")
        current[0]["content"] = "192.0.2.1"
        plan = trojan_node.plan_dns_change(current, self.node)
        self.assertEqual(plan, {"action": "update", "record_id": "record-1"})

    def test_dns_conflicts_fail_without_deletion(self):
        conflict_sets = [
            [
                {"id": "a1", "type": "A", "name": self.node.domain},
                {"id": "a2", "type": "A", "name": self.node.domain},
            ],
            [{"id": "aaaa", "type": "AAAA", "name": self.node.domain}],
            [{"id": "cname", "type": "CNAME", "name": self.node.domain}],
        ]
        for records in conflict_sets:
            with self.subTest(records=records):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.plan_dns_change(records, self.node)

    def test_apply_dns_uses_exact_create_or_overwrite_payload(self):
        calls = []

        class Client:
            def request(self, method, path, *, body=None, query=None):
                calls.append((method, path, body, query))
                return {"id": "result"}

        payload = {
            "type": "A", "name": self.node.domain,
            "content": self.node.address, "ttl": 1, "proxied": False,
        }
        trojan_node.apply_dns_change(Client(), "zone-1", self.node, {"action": "create"})
        trojan_node.apply_dns_change(
            Client(), "zone-1", self.node,
            {"action": "update", "record_id": "record-1"},
        )
        self.assertEqual(calls, [
            ("POST", "/zones/zone-1/dns_records", payload, None),
            ("PUT", "/zones/zone-1/dns_records/record-1", payload, None),
        ])

    def test_dns_write_requires_noop_readback(self):
        class Client:
            def __init__(self):
                self.written = False

            def request(self, _method, _path, *, body=None, query=None):
                self.written = True
                return {"id": "record-1"}

            def list_paginated(self, _path, _query=None):
                if not self.written:
                    return []
                return [{
                    "id": "record-1", "type": "A", "name": self_node.domain,
                    "content": self_node.address, "ttl": 1, "proxied": False,
                }]

        self_node = self.node
        client = Client()
        trojan_node.apply_dns_change_with_readback(
            client, "zone-1", self.node, {"action": "create"}
        )
        self.assertTrue(client.written)


class CloudflareTokenTests(unittest.TestCase):
    def setUp(self):
        self.manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        self.node = self.manifest.nodes["aiyun2"]

    def test_token_payload_has_dynamic_minimum_permissions_zone_and_source_ip(self):
        payload = trojan_node.build_dns_token_payload(
            self.node,
            "zone-id",
            {"Zone Read": "zone-read-id", "DNS Write": "dns-write-id"},
        )
        self.assertEqual(payload["name"], "trojan-aiyun2-dns01")
        self.assertEqual(payload["condition"], {
            "request_ip": {"in": ["69.33.3.215/32"]}
        })
        self.assertNotIn("expires_on", payload)
        policy = payload["policies"]
        self.assertEqual(len(policy), 1)
        self.assertEqual(policy[0]["resources"], {
            "com.cloudflare.api.account.zone.zone-id": "*"
        })
        self.assertEqual(
            {group["id"] for group in policy[0]["permission_groups"]},
            {"zone-read-id", "dns-write-id"},
        )

    def test_permission_group_resolution_is_exact_and_unique(self):
        groups = [
            {"id": "zr", "name": "Zone Read"},
            {"id": "dw", "name": "DNS Write"},
            {"id": "other", "name": "DNS Read"},
        ]
        self.assertEqual(trojan_node.resolve_permission_groups(groups), {
            "Zone Read": "zr", "DNS Write": "dw"
        })
        with self.assertRaises(trojan_node.SafetyError):
            trojan_node.resolve_permission_groups(groups + [{"id": "zr2", "name": "Zone Read"}])

    def test_permission_groups_use_the_single_page_api_without_pagination(self):
        calls = []

        class Client:
            def request(self, method, path):
                calls.append((method, path))
                return [
                    {"id": "zr", "name": "Zone Read"},
                    {"id": "dw", "name": "DNS Write"},
                ]

            def list_paginated(self, *_args, **_kwargs):
                raise AssertionError("permission groups API is not paginated")

        self.assertEqual(trojan_node._permission_groups(Client()), {
            "Zone Read": "zr", "DNS Write": "dw"
        })
        self.assertEqual(calls, [("GET", "/user/tokens/permission_groups")])

    def test_token_store_failure_revokes_new_token_and_preserves_old(self):
        revoked = []

        class Client:
            def list_tokens(self):
                return [{"id": "old-token", "name": self.node_name}]

            def create_token(self, _payload):
                return {"id": "new-token", "value": "new-test-token"}

            def revoke_token(self, token_id):
                revoked.append(token_id)

        client = Client()
        client.node_name = self.node.cloudflare_token_name
        with self.assertRaises(trojan_node.SafetyError):
            trojan_node.rotate_dns_token(
                client,
                self.manifest,
                self.node,
                "zone-id",
                {"Zone Read": "zr", "DNS Write": "dw"},
                store=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    trojan_node.SafetyError("store failed")
                ),
            )
        self.assertEqual(revoked, ["new-token"])

    def test_success_stores_before_revoking_exact_old_name(self):
        events = []
        list_calls = []

        class Client:
            def list_tokens(self):
                list_calls.append(True)
                if len(list_calls) == 1:
                    return [
                        {"id": "old-match", "name": self.node_name},
                        {"id": "unrelated", "name": "other-token"},
                    ]
                return [
                    {"id": "new-token", "name": self.node_name},
                    {"id": "unrelated", "name": "other-token"},
                ]

            def create_token(self, _payload):
                events.append("create")
                return {"id": "new-token", "value": "new-test-token"}

            def revoke_token(self, token_id):
                events.append("revoke:" + token_id)

        client = Client()
        client.node_name = self.node.cloudflare_token_name
        trojan_node.rotate_dns_token(
            client,
            self.manifest,
            self.node,
            "zone-id",
            {"Zone Read": "zr", "DNS Write": "dw"},
            store=lambda *_args, **_kwargs: events.append("store"),
        )
        self.assertEqual(events, ["create", "store", "revoke:old-match"])
        self.assertEqual(len(list_calls), 2)

    def test_revoke_exact_name_requires_empty_readback(self):
        state = [
            {"id": "match", "name": self.node.cloudflare_token_name},
            {"id": "other", "name": "other-token"},
        ]

        class Client:
            def list_tokens(self):
                return list(state)

            def revoke_token(self, token_id):
                state[:] = [token for token in state if token["id"] != token_id]

        count = trojan_node.revoke_named_node_tokens(Client(), self.node)
        self.assertEqual(count, 1)
        self.assertEqual(state, [{"id": "other", "name": "other-token"}])


class SshTrustTests(unittest.TestCase):
    def setUp(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        self.node = manifest.nodes["aiyun"]

    def test_existing_alias_ed25519_entry_is_the_only_trust_source(self):
        line = "aiyun ssh-ed25519 dGVzdC1wdWJsaWMta2V5\n"
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout=line, stderr="")

        result = trojan_node.load_trusted_known_host(
            self.node, pathlib.Path("/trusted/known_hosts"), runner=runner
        )
        self.assertEqual(result, line)
        self.assertEqual(calls[0][0], [
            "ssh-keygen", "-F", "aiyun", "-f", "/trusted/known_hosts",
        ])

    def test_missing_or_ambiguous_alias_ed25519_entry_is_rejected(self):
        cases = [
            subprocess.CompletedProcess([], 1, stdout="", stderr="missing"),
            subprocess.CompletedProcess(
                [], 0,
                stdout=(
                    "aiyun ssh-ed25519 dGVzdC1wdWJsaWMta2V5\n"
                    "aiyun ssh-ed25519 c2Vjb25kLWtleQ==\n"
                ),
                stderr="",
            ),
        ]
        for completed in cases:
            with self.subTest(completed=completed):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.load_trusted_known_host(
                        self.node,
                        pathlib.Path("/trusted/known_hosts"),
                        runner=lambda *_args, **_kwargs: completed,
                    )

    def test_verified_ssh_uses_only_dedicated_known_hosts(self):
        key_line = "aiyun ssh-ed25519 dGVzdC1wdWJsaWMta2V5\n"
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0] == "ssh-keygen":
                return subprocess.CompletedProcess(argv, 0, stdout=key_line, stderr="")
            known_hosts = pathlib.Path(next(
                item.split("=", 1)[1]
                for item in argv
                if item.startswith("UserKnownHostsFile=")
            ))
            self.assertEqual(known_hosts.read_text(), key_line)
            self.assertEqual(oct(known_hosts.stat().st_mode & 0o777), "0o600")
            return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

        output = trojan_node.run_verified_ssh(
            self.node,
            ["true"],
            runner=runner,
            known_hosts_path=pathlib.Path("/trusted/known_hosts"),
        )
        self.assertEqual(output, "ok\n")
        ssh_argv = calls[1][0]
        joined = " ".join(ssh_argv)
        self.assertIn("StrictHostKeyChecking=yes", joined)
        self.assertIn("GlobalKnownHostsFile=/dev/null", joined)
        self.assertIn("BatchMode=yes", joined)
        self.assertIn("HostKeyAlias=aiyun", joined)
        self.assertNotIn("StrictHostKeyChecking=no", joined)
        self.assertFalse(any(call[0][0] == "ssh-keyscan" for call in calls))
        known_hosts_arg = next(
            item for item in ssh_argv if item.startswith("UserKnownHostsFile=")
        )
        self.assertFalse(pathlib.Path(known_hosts_arg.split("=", 1)[1]).exists())

    def test_verified_ssh_quotes_multiline_remote_argv_as_one_command(self):
        key_line = "aiyun ssh-ed25519 dGVzdC1wdWJsaWMta2V5\n"
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0] == "ssh-keygen":
                return subprocess.CompletedProcess(argv, 0, stdout=key_line, stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="ok\n", stderr="")

        script = "set -eu\nprintf 'OS_ID=%s\\n' ubuntu\n"
        trojan_node.run_verified_ssh(
            self.node,
            ["sh", "-c", script],
            runner=runner,
            known_hosts_path=pathlib.Path("/trusted/known_hosts"),
        )

        ssh_argv = calls[1][0]
        self.assertEqual(ssh_argv[-2], "--")
        self.assertEqual(ssh_argv[-1], shlex.join(["sh", "-c", script]))

    def test_ssh_failure_is_sanitized(self):
        key_line = "aiyun ssh-ed25519 dGVzdC1wdWJsaWMta2V5\n"

        def runner(argv, **kwargs):
            if argv[0] == "ssh-keygen":
                return subprocess.CompletedProcess(argv, 0, stdout=key_line, stderr="")
            return subprocess.CompletedProcess(
                argv, 255, stdout="", stderr="remote sensitive diagnostic"
            )

        with self.assertRaises(trojan_node.SafetyError) as caught:
            trojan_node.run_verified_ssh(
                self.node,
                ["true"],
                runner=runner,
                known_hosts_path=pathlib.Path("/trusted/known_hosts"),
            )
        self.assertNotIn("sensitive diagnostic", str(caught.exception))


class DeploymentArtifactTests(unittest.TestCase):
    def setUp(self):
        manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")
        self.node = manifest.nodes["aiyun2"]

    def test_source_archive_requires_clean_repo_and_returns_exact_commit_hash(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[1:3] == ["status", "--porcelain"]:
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            if argv[1:3] == ["rev-parse", "HEAD"]:
                return subprocess.CompletedProcess(argv, 0, stdout="a" * 40 + "\n", stderr="")
            if argv[1] == "archive":
                return subprocess.CompletedProcess(argv, 0, stdout=b"archive-bytes", stderr=b"")
            raise AssertionError(argv)

        artifact = trojan_node.build_source_archive(ROOT, runner=runner)
        self.assertEqual(artifact.commit, "a" * 40)
        self.assertEqual(artifact.data, b"archive-bytes")
        self.assertEqual(
            artifact.sha256,
            "0c982986710a026635603031674053ca851fc0e3ea760094a34f59b84f7f6da6",
        )
        self.assertEqual(calls[2][0], [
            "git", "archive", "--format=tar", "a" * 40,
        ])

    def test_dirty_repo_stops_before_archive(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, stdout=" M README.md\n", stderr="")

        with self.assertRaisesRegex(trojan_node.SafetyError, "not clean"):
            trojan_node.build_source_archive(ROOT, runner=runner)
        self.assertEqual(len(calls), 1)

    def test_secret_tar_has_only_two_root_owned_0600_files(self):
        password = "test-password-secret"
        token = "test-cloudflare-secret"
        data = trojan_node.build_secret_tar(password, token)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            members = archive.getmembers()
            self.assertEqual([member.name for member in members], [
                "trojan-password", "cloudflare-token"
            ])
            self.assertTrue(all(member.mode == 0o600 for member in members))
            self.assertTrue(all(member.uid == 0 and member.gid == 0 for member in members))
            self.assertEqual(
                archive.extractfile(members[0]).read(), password.encode()
            )
            self.assertEqual(
                archive.extractfile(members[1]).read(), token.encode()
            )

    def test_remote_preflight_accepts_only_clean_ubuntu_2404(self):
        good = "\n".join([
            "OS_ID=ubuntu", "OS_VERSION=24.04", "ARCH=x86_64",
            "LISTEN_443=0", "MANAGED_STATE=0", "ACME_HOME=0", "PROVENANCE=0",
        ]) + "\n"
        result = trojan_node.validate_remote_preflight(good, self.node)
        self.assertEqual(result["ARCH"], "x86_64")
        self.assertEqual(result["STATE"], "clean")
        bad_values = [
            good.replace("24.04", "22.04"),
            good.replace("LISTEN_443=0", "LISTEN_443=1"),
            good.replace("MANAGED_STATE=0", "MANAGED_STATE=1"),
            good.replace("ACME_HOME=0", "ACME_HOME=1"),
            good.replace("PROVENANCE=0", "PROVENANCE=1"),
        ]
        for output in bad_values:
            with self.subTest(output=output):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.validate_remote_preflight(output, self.node)

    def test_remote_preflight_recognizes_only_complete_managed_candidate(self):
        managed = "\n".join([
            "OS_ID=ubuntu", "OS_VERSION=24.04", "ARCH=x86_64",
            "LISTEN_443=1", "MANAGED_STATE=13", "ACME_HOME=1", "PROVENANCE=1",
        ]) + "\n"
        result = trojan_node.validate_remote_preflight(managed, self.node)
        self.assertEqual(result["STATE"], "managed")
        for broken in (
            managed.replace("LISTEN_443=1", "LISTEN_443=0"),
            managed.replace("MANAGED_STATE=13", "MANAGED_STATE=0"),
            managed.replace("ACME_HOME=1", "ACME_HOME=0"),
            managed.replace("PROVENANCE=1", "PROVENANCE=2"),
        ):
            with self.subTest(broken=broken):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.validate_remote_preflight(broken, self.node)

    def test_stage_and_install_never_place_secrets_in_remote_argv(self):
        artifact = trojan_node.SourceArtifact(
            commit="b" * 40, sha256="c" * 64, data=b"archive"
        )
        calls = []
        password = "test-password-secret"
        token = "test-cloudflare-secret"

        def ssh_runner(node, remote_argv, *, input_data=None):
            calls.append((node, remote_argv, input_data))
            return "ok\n"

        trojan_node.stage_and_install(
            self.node, artifact, password, token, ssh_runner=ssh_runner
        )
        self.assertEqual(len(calls), 2)
        argv_text = " ".join(part for call in calls for part in call[1])
        self.assertNotIn(password, argv_text)
        self.assertNotIn(token, argv_text)
        self.assertEqual(calls[0][2], artifact.data)
        self.assertIsInstance(calls[1][2], bytes)

    def test_deployment_plan_is_redacted_and_exact(self):
        artifact = trojan_node.SourceArtifact(
            commit="b" * 40, sha256="c" * 64, data=b"archive"
        )
        plan = trojan_node.build_deployment_plan(
            self.node,
            artifact,
            {"action": "update", "record_id": "record-1"},
            rotate_secrets=True,
        )
        rendered = json.dumps(plan, sort_keys=True)
        self.assertEqual(plan["node"], "aiyun2")
        self.assertEqual(plan["gitCommit"], "b" * 40)
        self.assertEqual(plan["dnsAction"], "update")
        self.assertNotIn("password", rendered.lower())
        self.assertNotIn("tokenValue", rendered)

    def test_apply_confirmation_requires_exact_node_name(self):
        self.assertTrue(trojan_node.confirm_node(self.node, reader=lambda _prompt: "aiyun2"))
        self.assertFalse(trojan_node.confirm_node(self.node, reader=lambda _prompt: "AIYUN2"))
        self.assertFalse(trojan_node.confirm_node(self.node, reader=lambda _prompt: "aiyun"))


class ManagedProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.node = trojan_node.load_manifest(
            ROOT / "config" / "nodes.json"
        ).nodes["aiyun2"]
        self.artifact = trojan_node.SourceArtifact("a" * 40, "b" * 64, b"archive")

    def test_provenance_binds_only_node_and_exact_source(self):
        payload = trojan_node.build_managed_provenance(self.node, self.artifact)
        self.assertEqual(payload, {
            "schemaVersion": 1,
            "node": "aiyun2",
            "address": "69.33.3.215",
            "domain": "introspect2.czyhandsome.ink",
            "gitCommit": "a" * 40,
            "archiveSha256": "b" * 64,
        })
        rendered = json.dumps(payload)
        self.assertNotIn("password", rendered.lower())
        self.assertNotIn("token", rendered.lower())

    def test_provenance_rejects_mismatch_missing_or_extra_fields(self):
        valid = trojan_node.build_managed_provenance(self.node, self.artifact)
        trojan_node.validate_managed_provenance(valid, self.node, self.artifact)
        invalid = [
            {**valid, "gitCommit": "c" * 40},
            {key: value for key, value in valid.items() if key != "domain"},
            {**valid, "unexpected": True},
        ]
        for payload in invalid:
            with self.subTest(payload=payload):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.validate_managed_provenance(
                        payload, self.node, self.artifact
                    )

    def test_provenance_write_is_root_only_atomic_and_strictly_read_back(self):
        calls = []

        def ssh_runner(node, remote_argv, *, input_data=None):
            calls.append((node, remote_argv, input_data))
            if input_data is None:
                return json.dumps(
                    trojan_node.build_managed_provenance(node, self.artifact)
                ) + "\n"
            return ""

        result = trojan_node.write_managed_provenance(
            self.node, self.artifact, ssh_runner=ssh_runner
        )
        self.assertEqual(result["gitCommit"], "a" * 40)
        self.assertEqual(len(calls), 2)
        script = " ".join(calls[0][1])
        self.assertIn("root:root", script)
        self.assertIn("0600", script)
        self.assertIn("mv", script)
        self.assertIsInstance(calls[0][2], bytes)

    def test_managed_rerun_requires_matching_marker_and_healthy_service(self):
        remote = {"STATE": "managed"}
        with mock.patch.object(
            trojan_node,
            "read_managed_provenance",
            return_value=trojan_node.build_managed_provenance(self.node, self.artifact),
        ), mock.patch.object(
            trojan_node, "server_snapshot", return_value={"CERT_SHA256": "c" * 64}
        ) as snapshot, mock.patch.object(trojan_node, "verify_online_tls") as tls:
            trojan_node.validate_deployable_remote(
                self.node, self.artifact, remote
            )
        snapshot.assert_called_once_with(self.node)
        tls.assert_called_once_with(self.node, expected_sha256="c" * 64)

    def test_managed_rerun_refuses_secret_rotation(self):
        with self.assertRaisesRegex(trojan_node.SafetyError, "rotate-secrets"):
            trojan_node.require_rerun_secret_policy(
                {"STATE": "managed"}, rotate_secrets=True, node=self.node
            )


class ServerVerificationTests(unittest.TestCase):
    def setUp(self):
        self.node = trojan_node.load_manifest(
            ROOT / "config" / "nodes.json"
        ).nodes["aiyun"]
        self.good = "\n".join([
            "ACTIVE=active",
            "ENABLED=enabled",
            "PID=4242",
            "NRESTARTS=0",
            "OWNER=xray",
            "QUEUE=0/4096",
            "CONFIG_MODE=640",
            "CONFIG_OWNER=root:xray",
            "RENEW_ACTIVE=active",
            "RENEW_ENABLED=enabled",
            "SNAPSHOT_ACTIVE=active",
            "SNAPSHOT_ENABLED=enabled",
            "CERTMAN_STATUS=ok",
            "PORT_80=0",
            "PORT_18443=0",
            "PORT_34384=0",
            "TLS_SAN=1",
            "CONFIG_SHA256=" + "a" * 64,
            "CERT_SHA256=" + "b" * 64,
        ]) + "\n"

    def test_server_snapshot_requires_every_acceptance_fact(self):
        facts = trojan_node.validate_server_snapshot(self.good, self.node)
        self.assertEqual(facts["PID"], "4242")
        self.assertEqual(facts["QUEUE"], "0/4096")

    def test_server_snapshot_rejects_restart_queue_owner_ports_or_tls(self):
        bad = [
            self.good.replace("NRESTARTS=0", "NRESTARTS=1"),
            self.good.replace("QUEUE=0/4096", "QUEUE=1/128"),
            self.good.replace("OWNER=xray", "OWNER=unknown"),
            self.good.replace("PORT_80=0", "PORT_80=1"),
            self.good.replace("TLS_SAN=1", "TLS_SAN=0"),
            self.good.replace("CERTMAN_STATUS=ok", "CERTMAN_STATUS=failed"),
        ]
        for output in bad:
            with self.subTest(output=output):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.validate_server_snapshot(output, self.node)

    def test_idempotent_identity_ignores_observation_only_fields(self):
        before = trojan_node.validate_server_snapshot(self.good, self.node)
        after = dict(before)
        self.assertTrue(trojan_node.same_install_identity(before, after))
        after["PID"] = "9999"
        self.assertFalse(trojan_node.same_install_identity(before, after))


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.manifest = trojan_node.load_manifest(ROOT / "config" / "nodes.json")

    def test_credentials_status_dispatch_prints_only_masked_states(self):
        args = trojan_node.build_parser().parse_args([
            "credentials", "status", "--node", "aiyun"
        ])
        output = io.StringIO()
        with mock.patch.object(
            trojan_node,
            "credentials_status",
            return_value={"password": "PRESENT", "cloudflare-token": "MISSING"},
        ), mock.patch.object(trojan_node.sys, "stdout", output):
            rc = trojan_node.execute_command(
                args, self.manifest, trojan_node.SecretBundle(None, None, None)
            )
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(output.getvalue())["fields"], {
            "password": "PRESENT", "cloudflare-token": "MISSING"
        })

    def test_unknown_node_error_lists_available_ids(self):
        args = trojan_node.build_parser().parse_args([
            "host", "check", "--node", "missing"
        ])
        with self.assertRaisesRegex(
            trojan_node.SafetyError, "available nodes: aiyun, aiyun2"
        ):
            trojan_node.execute_command(
                args, self.manifest, trojan_node.SecretBundle(None, None, None)
            )

    def test_deploy_without_apply_is_redacted_and_never_installs(self):
        args = trojan_node.build_parser().parse_args([
            "deploy", "--node", "aiyun2", "--rotate-secrets"
        ])
        artifact = trojan_node.SourceArtifact("a" * 40, "b" * 64, b"archive")
        output = io.StringIO()
        with mock.patch.object(trojan_node, "CloudflareClient"), \
             mock.patch.object(trojan_node, "warn_manager_token_expiry"), \
             mock.patch.object(
                 trojan_node, "resolve_unique_zone",
                 return_value={"id": "zone-1", "name": self.manifest.zone, "status": "active"},
             ), \
             mock.patch.object(trojan_node, "list_node_dns_records", return_value=[]), \
             mock.patch.object(
                 trojan_node, "run_remote_preflight", return_value={"STATE": "clean"}
             ), \
             mock.patch.object(trojan_node, "build_source_archive", return_value=artifact), \
             mock.patch.object(trojan_node, "stage_and_install") as install, \
             mock.patch.object(trojan_node.sys, "stdout", output):
            rc = trojan_node.execute_command(
                args,
                self.manifest,
                trojan_node.SecretBundle("manager-test", None, None),
            )
        self.assertEqual(rc, 0)
        install.assert_not_called()
        plan = json.loads(output.getvalue())
        self.assertEqual(plan["node"], "aiyun2")
        self.assertEqual(plan["dnsAction"], "create")
        self.assertNotIn("manager-test", output.getvalue())

    def test_managed_deploy_validates_marker_and_writes_it_before_acceptance(self):
        args = trojan_node.build_parser().parse_args([
            "deploy", "--node", "aiyun2", "--apply",
        ])
        artifact = trojan_node.SourceArtifact("a" * 40, "b" * 64, b"archive")
        snapshot = {
            "PID": "4242", "NRESTARTS": "0",
            "CONFIG_SHA256": "c" * 64, "CERT_SHA256": "d" * 64,
        }
        events = []
        output = io.StringIO()

        with mock.patch.object(
            trojan_node, "credentials_status",
            return_value={"password": "PRESENT", "cloudflare-token": "PRESENT"},
        ), mock.patch.object(trojan_node, "CloudflareClient"), \
             mock.patch.object(trojan_node, "warn_manager_token_expiry"), \
             mock.patch.object(
                 trojan_node, "resolve_unique_zone",
                 return_value={"id": "zone-1", "name": self.manifest.zone, "status": "active"},
             ), mock.patch.object(
                 trojan_node, "list_node_dns_records",
                 return_value=[{
                     "id": "record-1", "type": "A",
                     "name": self.manifest.nodes["aiyun2"].domain,
                     "content": self.manifest.nodes["aiyun2"].address,
                     "ttl": 1, "proxied": False,
                 }],
             ), mock.patch.object(
                 trojan_node, "run_remote_preflight", return_value={"STATE": "managed"}
             ), mock.patch.object(
                 trojan_node, "build_source_archive", return_value=artifact
             ), mock.patch.object(
                 trojan_node, "validate_deployable_remote",
                 side_effect=lambda *_args: events.append("validate-provenance"),
             ), mock.patch.object(
                 trojan_node, "validate_local_acceptance_prerequisites",
                 side_effect=lambda: events.append("local-prerequisites"),
             ), mock.patch.object(
                 trojan_node, "confirm_node", return_value=True
             ), mock.patch.object(
                 trojan_node, "apply_dns_change_with_readback",
                 side_effect=lambda *_args: events.append("dns-apply"),
             ), mock.patch.object(
                 trojan_node, "stage_and_install",
                 side_effect=lambda *_args: events.append("install"),
             ), mock.patch.object(
                 trojan_node, "server_snapshot", return_value=snapshot
             ), mock.patch.object(
                 trojan_node, "verify_online_tls",
                 side_effect=lambda *_args, **_kwargs: events.append("tls"),
             ), mock.patch.object(
                 trojan_node, "write_managed_provenance",
                 side_effect=lambda *_args, **_kwargs: events.append("write-provenance"),
             ), mock.patch.object(
                 trojan_node, "run_mihomo_acceptance",
                 side_effect=lambda *_args, **_kwargs: events.append("acceptance"),
             ), mock.patch.object(trojan_node.sys, "stdout", output):
            rc = trojan_node.execute_command(
                args,
                self.manifest,
                trojan_node.SecretBundle(
                    "manager-test", "password-test", "node-token-test"
                ),
                reader=lambda _prompt: "aiyun2",
            )

        self.assertEqual(rc, 0)
        self.assertEqual(events, [
            "validate-provenance", "local-prerequisites", "dns-apply",
            "install", "install", "tls",
            "write-provenance", "acceptance",
        ])

    def test_client_failure_reports_completed_side_effects_and_safe_resume(self):
        args = trojan_node.build_parser().parse_args([
            "deploy", "--node", "aiyun2", "--apply",
        ])
        node = self.manifest.nodes["aiyun2"]
        artifact = trojan_node.SourceArtifact("a" * 40, "b" * 64, b"archive")
        snapshot = {
            "PID": "4242", "NRESTARTS": "0",
            "CONFIG_SHA256": "c" * 64, "CERT_SHA256": "d" * 64,
        }
        stderr = io.StringIO()
        with mock.patch.object(
            trojan_node, "credentials_status",
            return_value={"password": "PRESENT", "cloudflare-token": "PRESENT"},
        ), mock.patch.object(trojan_node, "CloudflareClient"), \
             mock.patch.object(trojan_node, "warn_manager_token_expiry"), \
             mock.patch.object(
                 trojan_node, "resolve_unique_zone",
                 return_value={"id": "zone-1", "name": node.zone, "status": "active"},
             ), mock.patch.object(
                 trojan_node, "list_node_dns_records",
                 return_value=[{
                     "id": "record-1", "type": "A", "name": node.domain,
                     "content": node.address, "ttl": 1, "proxied": False,
                 }],
             ), mock.patch.object(
                 trojan_node, "run_remote_preflight", return_value={"STATE": "managed"}
             ), mock.patch.object(
                 trojan_node, "build_source_archive", return_value=artifact
             ), mock.patch.object(trojan_node, "validate_deployable_remote"), \
             mock.patch.object(
                 trojan_node, "validate_local_acceptance_prerequisites"
             ), \
             mock.patch.object(trojan_node, "confirm_node", return_value=True), \
             mock.patch.object(trojan_node, "apply_dns_change_with_readback"), \
             mock.patch.object(trojan_node, "stage_and_install"), \
             mock.patch.object(trojan_node, "server_snapshot", return_value=snapshot), \
             mock.patch.object(trojan_node, "verify_online_tls"), \
             mock.patch.object(trojan_node, "write_managed_provenance"), \
             mock.patch.object(
                 trojan_node, "run_mihomo_acceptance",
                 side_effect=trojan_node.SafetyError("client failed"),
             ), mock.patch.object(trojan_node.sys, "stderr", stderr):
            with self.assertRaisesRegex(trojan_node.SafetyError, "client failed"):
                trojan_node.execute_command(
                    args,
                    self.manifest,
                    trojan_node.SecretBundle(
                        "manager-test", "password-test", "node-token-test"
                    ),
                    reader=lambda _prompt: "aiyun2",
                )

        diagnostic = stderr.getvalue()
        self.assertIn("stage=client-acceptance", diagnostic)
        self.assertIn("serverInstalled=true", diagnostic)
        self.assertIn("provenanceWritten=true", diagnostic)
        self.assertIn(
            "safeResume=trojan-node verify --node aiyun2", diagnostic
        )


class ClientAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.node = trojan_node.load_manifest(
            ROOT / "config" / "nodes.json"
        ).nodes["aiyun2"]

    def test_online_certificate_requires_matching_der_hash(self):
        der = b"test-certificate-der"
        expected = trojan_node.hashlib.sha256(der).hexdigest()
        self.assertEqual(
            trojan_node.validate_online_certificate(der, expected, self.node),
            expected,
        )
        with self.assertRaises(trojan_node.SafetyError):
            trojan_node.validate_online_certificate(der, "0" * 64, self.node)

    def test_mihomo_config_uses_ip_sni_and_strict_certificate(self):
        secret = "test-only-trojan-password"
        config = trojan_node.render_mihomo_config(self.node, secret, 17890)
        self.assertIn('server: "69.33.3.215"', config)
        self.assertIn('sni: "introspect2.czyhandsome.ink"', config)
        self.assertIn('skip-cert-verify: false', config)
        self.assertIn(secret, config)
        self.assertNotIn("tun:", config.lower())

    def test_acceptance_port_is_allocated_by_the_kernel(self):
        probe = mock.MagicMock()
        probe.getsockname.return_value = ("127.0.0.1", 45678)
        with mock.patch.object(trojan_node.socket, "socket", return_value=probe):
            self.assertEqual(trojan_node.allocate_acceptance_port(), 45678)
        probe.bind.assert_called_once_with(("127.0.0.1", 0))
        probe.close.assert_called_once_with()

    def test_mihomo_start_retries_after_local_port_race(self):
        first = mock.MagicMock()
        first.poll.return_value = 1
        second = mock.MagicMock()
        second.poll.return_value = None
        connection = mock.MagicMock()
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            trojan_node, "allocate_acceptance_port", side_effect=[40001, 40002]
        ), mock.patch.object(
            trojan_node.subprocess, "Popen", side_effect=[first, second]
        ) as popen, mock.patch.object(
            trojan_node.socket, "create_connection", return_value=connection
        ):
            process, port = trojan_node.start_isolated_mihomo(
                "/usr/local/bin/mihomo",
                temp_dir,
                self.node,
                "test-only-password",
            )
        self.assertIs(process, second)
        self.assertEqual(port, 40002)
        self.assertEqual(popen.call_count, 2)

    def test_mihomo_version_accepts_current_bugfix_releases(self):
        self.assertEqual(
            trojan_node.validate_mihomo_version(
                "Mihomo Meta 1.19.30 darwin arm64 with go1.26.6"
            ),
            (1, 19, 30),
        )

    def test_mihomo_version_rejects_older_or_unparseable_output(self):
        for output in (
            "Mihomo Meta v1.19.28 darwin arm64",
            "unexpected version output",
        ):
            with self.subTest(output=output):
                with self.assertRaises(trojan_node.SafetyError):
                    trojan_node.validate_mihomo_version(output)

    def test_local_acceptance_prerequisites_require_mihomo_and_gcp_host_key(self):
        calls = []

        def runner(argv, **_kwargs):
            calls.append(argv)
            if argv[0] == "/usr/local/bin/mihomo":
                return subprocess.CompletedProcess(
                    argv, 0, "Mihomo Meta v1.19.30 darwin arm64", ""
                )
            return subprocess.CompletedProcess(
                argv, 0, "[34.31.209.55]:50245 ssh-ed25519 AAAATEST", ""
            )

        with mock.patch.object(
            trojan_node.shutil, "which", return_value="/usr/local/bin/mihomo"
        ):
            trojan_node.validate_local_acceptance_prerequisites(runner=runner)
        self.assertEqual(calls[0], ["/usr/local/bin/mihomo", "-v"])
        self.assertEqual(calls[1][0:3], ["ssh-keygen", "-F", "[34.31.209.55]:50245"])

    def test_gcp_ssh_acceptance_argv_is_proxy_bound_and_secret_free(self):
        reconnect = trojan_node.gcp_ssh_argv(17890, keepalive_seconds=None)
        soak = trojan_node.gcp_ssh_argv(17890, keepalive_seconds=3600)
        joined = " ".join(reconnect)
        self.assertIn("caoziyu@34.31.209.55", joined)
        self.assertIn("50245", reconnect)
        self.assertIn("ProxyCommand=", joined)
        self.assertIn("127.0.0.1:17890", joined)
        self.assertEqual(soak[-2:], ["sleep", "3600"])
        self.assertIn("ServerAliveInterval=30", " ".join(soak))

    def test_reconnect_checks_report_bounded_progress(self):
        stream = io.StringIO()
        reporter = trojan_node.ProgressReporter(stream=stream)
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(
            trojan_node.subprocess, "run", return_value=completed
        ) as run:
            trojan_node.run_gcp_reconnects(
                self.node, 45678, reconnects=3, reporter=reporter
            )
        self.assertEqual(run.call_count, 3)
        progress = stream.getvalue()
        self.assertIn("reconnect=1/3", progress)
        self.assertIn("reconnect=3/3", progress)


if __name__ == "__main__":
    unittest.main()
