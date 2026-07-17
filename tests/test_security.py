import base64
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

import server


WEB_PASSWORD = "local-test-password"


def sample_config(root):
    return server.normalize_config(
        {
            "settings": {
                "outputDir": str(root / "recordings"),
                "ffmpegPath": str(root / "bin" / "ffmpeg"),
                "ffprobePath": str(root / "bin" / "ffprobe"),
                "webUser": "admin",
                "webPassword": WEB_PASSWORD,
                "t2uDllPath": str(root / "native" / "libt2u.so"),
                "t2uServerKey": "settings-server-key",
                "t2uDevicePassword": "settings-device-password",
            },
            "t2uClouds": [
                {
                    "id": "cloud-1",
                    "name": "Cloud 1",
                    "t2uDllPath": str(root / "native" / "cloud-libt2u.so"),
                    "t2uServer": "t2u.invalid",
                    "t2uServerPort": 9000,
                    "t2uServerKey": "cloud-server-key",
                    "t2uDevicePassword": "cloud-device-password",
                }
            ],
            "sourceGroups": [
                {
                    "id": "group-1",
                    "name": "Group 1",
                    "t2uCloudId": "cloud-1",
                    "p2pUuid": "device-1",
                    "p2pPassword": "p2p-secret",
                    "rtspUser": "viewer",
                    "rtspPassword": "rtsp-secret",
                }
            ],
            "cameras": [
                {
                    "id": "camera-1",
                    "name": "Camera 1",
                    "type": "stream",
                    "url": "rtsp://viewer:url-secret@192.0.2.10:554/live",
                    "enabled": True,
                }
            ],
        }
    )


class SecurityHelpersTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = sample_config(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_public_config_redacts_secrets_urls_and_server_paths(self):
        self.config["cameras"].append(
            {
                "id": "camera-2",
                "name": "Camera 2",
                "type": "stream",
                "url": "https://camera.invalid/live?token=query-secret",
                "enabled": True,
            }
        )
        visible = server.public_config(self.config)
        serialized = json.dumps(visible)

        for secret in (
            "settings-server-key",
            "settings-device-password",
            "cloud-server-key",
            "cloud-device-password",
            "p2p-secret",
            "rtsp-secret",
            "url-secret",
            "query-secret",
            self.config["settings"]["webPassword"],
            str(self.root),
        ):
            self.assertNotIn(secret, serialized)

        self.assertTrue(visible["settings"]["webPasswordConfigured"])
        self.assertTrue(visible["t2uClouds"][0]["t2uServerKeyConfigured"])
        self.assertTrue(visible["sourceGroups"][0]["rtspPasswordConfigured"])
        self.assertEqual(visible["cameras"][0]["url"], "")
        self.assertEqual(visible["cameras"][1]["url"], "")
        self.assertTrue(visible["cameras"][0]["urlCredentialsConfigured"])
        self.assertNotIn("outputDir", visible["settings"])
        self.assertNotIn("t2uDllPath", visible["t2uClouds"][0])

    def test_local_file_stream_protocol_is_rejected(self):
        camera = {
            "name": "Local file",
            "type": "stream",
            "url": "file:///etc/passwd",
        }
        with self.assertRaises(ValueError):
            server.validate_camera(camera, self.config)

    def test_config_update_preserves_omitted_secrets_and_paths(self):
        visible = server.public_config(self.config)
        visible["t2uClouds"][0]["name"] = "Renamed"
        visible["settings"]["outputDir"] = str(self.root / "attacker-output")
        visible["t2uClouds"][0]["t2uDllPath"] = str(self.root / "attacker.dll")

        updated = server.normalize_config(server.prepare_config_update(self.config, visible))

        self.assertEqual(updated["t2uClouds"][0]["name"], "Renamed")
        self.assertEqual(updated["settings"]["outputDir"], self.config["settings"]["outputDir"])
        self.assertEqual(updated["t2uClouds"][0]["t2uDllPath"], self.config["t2uClouds"][0]["t2uDllPath"])
        self.assertEqual(updated["t2uClouds"][0]["t2uServerKey"], "cloud-server-key")
        self.assertEqual(updated["sourceGroups"][0]["p2pPassword"], "p2p-secret")
        self.assertEqual(updated["cameras"][0]["url"], self.config["cameras"][0]["url"])

        visible["t2uClouds"][0]["t2uServerKey"] = "replacement-key"
        replaced = server.normalize_config(server.prepare_config_update(self.config, visible))
        self.assertEqual(replaced["t2uClouds"][0]["t2uServerKey"], "replacement-key")

        self.config["cameras"][0]["url"] = "https://camera.invalid/live?token=query-secret"
        preserved = server.normalize_config(
            server.prepare_config_update(self.config, server.public_config(self.config))
        )
        self.assertEqual(preserved["cameras"][0]["url"], self.config["cameras"][0]["url"])

    def test_public_bind_requires_password_and_tls_or_explicit_override(self):
        no_password = sample_config(self.root)
        no_password["settings"]["webPassword"] = ""

        server.validate_web_access_config(no_password, "127.0.0.1")
        with self.assertRaises(ValueError):
            server.validate_web_access_config(no_password, "0.0.0.0", is_tls=True)
        with self.assertRaises(ValueError):
            server.validate_web_access_config(self.config, "0.0.0.0")
        server.validate_web_access_config(self.config, "0.0.0.0", is_tls=True)
        server.validate_web_access_config(self.config, "0.0.0.0", allow_insecure_http=True)

    def test_origin_matching_is_exact(self):
        self.assertTrue(server.origin_matches_host("https://recorder.example", "recorder.example"))
        self.assertTrue(server.origin_matches_host("http://127.0.0.1:8088", "127.0.0.1:8088"))
        self.assertFalse(server.origin_matches_host("https://evil.example", "recorder.example"))
        self.assertFalse(server.origin_matches_host("null", "recorder.example"))

    def test_preview_slots_are_bounded_and_released(self):
        with server.PREVIEW_LOCK:
            server.ACTIVE_PREVIEWS.clear()
        with mock.patch.dict(
            os.environ,
            {
                "CAMERA_RECORDER_MAX_PREVIEWS": "1",
                "CAMERA_RECORDER_MAX_PREVIEWS_PER_CLIENT": "1",
            },
        ):
            token, _max_seconds = server.acquire_preview_slot("192.0.2.20", "camera-1")
            with self.assertRaises(server.PreviewLimitError):
                server.acquire_preview_slot("192.0.2.21", "camera-2")
            server.release_preview_slot(token)
            replacement, _max_seconds = server.acquire_preview_slot("192.0.2.21", "camera-2")
            server.release_preview_slot(replacement)

    def test_authentication_failures_trigger_temporary_block(self):
        client_ip = "192.0.2.30"
        server.clear_authentication_failures(client_ip)
        for _attempt in range(server.AUTH_MAX_FAILURES - 1):
            self.assertEqual(server.record_authentication_failure(client_ip), 0)
        self.assertEqual(server.record_authentication_failure(client_ip), server.AUTH_BLOCK_SECONDS)
        self.assertGreater(server.authentication_retry_after(client_ip), 0)
        server.clear_authentication_failures(client_ip)

    def test_t2u_tunnel_retries_with_a_new_mapping(self):
        class FakeDll:
            def __init__(self):
                self.added = []
                self.deleted = []

            def t2u_add_port_v3(self, *_args):
                port = 12000 + len(self.added)
                self.added.append(port)
                return port

            def t2u_port_status(self, port, _stat):
                return 1 if port == 12001 else 0

            def t2u_del_port(self, port):
                self.deleted.append(port)

        runtime = server.T2uRuntime()
        runtime._dll = FakeDll()
        clock = [0.0]

        def monotonic():
            clock[0] += 1.0
            return clock[0]

        with mock.patch.object(runtime, "wait_until_ready"), mock.patch.object(
            server.time, "monotonic", side_effect=monotonic
        ), mock.patch.object(server.time, "sleep"):
            tunnel = runtime.open_tunnel(
                {
                    "p2pUuid": "device-1",
                    "p2pPassword": "secret",
                    "p2pRemoteIp": "127.0.0.1",
                    "p2pRemotePort": 554,
                },
                {"t2uConnectTimeoutSeconds": 30},
            )

        self.assertEqual(tunnel.local_port, 12001)
        self.assertEqual(runtime._dll.added, [12000, 12001])
        self.assertEqual(runtime._dll.deleted, [12000])
        tunnel.close()


class SecurityHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.original_data_dir = server.DATA_DIR
        cls.original_config_path = server.CONFIG_PATH
        server.DATA_DIR = cls.root / "data"
        server.CONFIG_PATH = server.DATA_DIR / "config.json"
        server.save_config(sample_config(cls.root))
        cls.httpd = server.RecorderServer(("127.0.0.1", 0), server.RequestHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]
        token = base64.b64encode(f"admin:{WEB_PASSWORD}".encode("utf-8")).decode("ascii")
        cls.auth_headers = {"Authorization": f"Basic {token}"}

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=3)
        server.DATA_DIR = cls.original_data_dir
        server.CONFIG_PATH = cls.original_config_path
        cls.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        request_headers = {**self.auth_headers, **(headers or {})}
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = dict(response.getheaders())
        connection.close()
        return response.status, response_headers, payload

    def test_state_and_static_responses_are_hardened(self):
        status, headers, body = self.request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", headers.get("Content-Security-Policy", ""))

        serialized = body.decode("utf-8")
        self.assertNotIn("cloud-server-key", serialized)
        self.assertNotIn("rtsp-secret", serialized)
        self.assertNotIn("url-secret", serialized)
        self.assertNotIn(str(self.root), serialized)

        status, headers, _body = self.request("GET", "/index.html")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Referrer-Policy"), "no-referrer")

    def test_cross_origin_mutation_is_rejected(self):
        status, _headers, body = self.request(
            "POST",
            "/api/config",
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": "https://evil.example",
                "X-Recorder-Request": "1",
            },
        )
        self.assertEqual(status, 403)
        self.assertIn("nao permitida", body.decode("utf-8"))

    def test_mutation_without_security_marker_is_rejected(self):
        status, _headers, body = self.request(
            "POST",
            "/api/config",
            body=b"{}",
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertIn("Cabecalho de seguranca", body.decode("utf-8"))

    def test_same_origin_config_update_preserves_redacted_values(self):
        status, _headers, body = self.request(
            "POST",
            "/api/config",
            body=b"{}",
            headers={
                "Content-Type": "application/json",
                "Origin": f"http://127.0.0.1:{self.port}",
                "X-Recorder-Request": "1",
            },
        )
        self.assertEqual(status, 200)
        serialized = body.decode("utf-8")
        self.assertNotIn("cloud-server-key", serialized)
        self.assertNotIn("url-secret", serialized)
        stored = server.load_config()
        self.assertEqual(stored["t2uClouds"][0]["t2uServerKey"], "cloud-server-key")
        self.assertIn("url-secret", stored["cameras"][0]["url"])

    def test_config_file_permissions_are_private_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX permissions are enforced on Linux deployments")
        self.assertEqual(server.CONFIG_PATH.stat().st_mode & 0o777, 0o600)
        self.assertEqual(server.DATA_DIR.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
