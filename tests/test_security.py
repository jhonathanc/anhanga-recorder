import base64
import http.client
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
from urllib.parse import quote

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

    def test_rtsp_service_unavailable_detection_is_specific(self):
        self.assertTrue(
            server.is_rtsp_service_unavailable(
                "[rtsp @ 0x1234] method OPTIONS failed: 503 Service Unavailable"
            )
        )
        self.assertFalse(server.is_rtsp_service_unavailable("method DESCRIBE failed: 503 Service Unavailable"))
        self.assertFalse(server.is_rtsp_service_unavailable("method OPTIONS failed: 401 Unauthorized"))

    def test_recording_catalog_groups_by_segment_date_and_camera(self):
        self.config["cameras"].append(
            {
                "id": "camera-2",
                "name": "Camera 2",
                "type": "stream",
                "url": "rtsp://192.0.2.11/live",
                "enabled": True,
            }
        )
        output = Path(self.config["settings"]["outputDir"])
        files = {
            "Camera_1/2026-07-19/Camera_1_20260719_234500.mkv": b"older",
            "Camera_1/2026-07-19/Camera_1_20260720_001500.mkv": b"after-midnight",
            "Camera_2/2026-07-20/Camera_2_20260720_010000.mkv": b"second-camera",
        }
        for relative, content in files.items():
            target = output / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)

        with mock.patch.object(server, "load_config", return_value=self.config):
            catalog = server.recording_catalog()
            camera_two = server.recording_catalog("2026-07-20", "Camera_2")

        self.assertEqual(catalog["selectedDate"], "2026-07-20")
        self.assertEqual([item["date"] for item in catalog["dates"]], ["2026-07-20", "2026-07-19"])
        self.assertEqual(catalog["dates"][0]["cameraCount"], 2)
        self.assertEqual([item["name"] for item in catalog["cameras"]], ["Camera 1", "Camera 2"])
        self.assertEqual(catalog["recordings"][0]["time"], "00:15:00")
        self.assertEqual(camera_two["recordings"][0]["name"], "Camera_2_20260720_010000.mkv")

    def test_recording_file_resolution_stays_inside_output_directory(self):
        output = Path(self.config["settings"]["outputDir"])
        target = output / "Camera_1" / "2026-07-20" / "Camera_1_20260720_010000.mkv"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"video")

        with mock.patch.object(server, "load_config", return_value=self.config):
            self.assertEqual(
                server.resolve_recording_file("Camera_1/2026-07-20/Camera_1_20260720_010000.mkv"),
                target.resolve(),
            )
            with self.assertRaises(FileNotFoundError):
                server.resolve_recording_file("../outside.mkv")
            with self.assertRaises(FileNotFoundError):
                server.resolve_recording_file(".private/secret.mkv")

    def test_byte_ranges_cover_full_open_and_suffix_forms(self):
        self.assertEqual(server.parse_byte_range(None, 10), (0, 9, False))
        self.assertEqual(server.parse_byte_range("bytes=2-5", 10), (2, 5, True))
        self.assertEqual(server.parse_byte_range("bytes=7-", 10), (7, 9, True))
        self.assertEqual(server.parse_byte_range("bytes=-3", 10), (7, 9, True))
        with self.assertRaises(ValueError):
            server.parse_byte_range("bytes=10-12", 10)

    def test_preview_retries_rtsp_503_on_the_same_tunnel(self):
        class FakeProcess:
            def __init__(self, stdout, stderr, returncode):
                self.stdout = io.BytesIO(stdout)
                self.stderr = io.BytesIO(stderr)
                self.returncode = returncode

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        class FakeTunnel:
            local_port = 12000
            reused = False
            use_count = 1

            def close(self):
                return {"closed": True, "localPort": self.local_port}

        class FakeHandler:
            def __init__(self):
                self.statuses = []
                self.headers = []
                self.wfile = io.BytesIO()
                self.server = type("FakeServer", (), {"is_tls": False})()

            def client_ip(self):
                return "192.0.2.40"

            def send_response(self, status):
                self.statuses.append(status)

            def send_header(self, name, value):
                self.headers.append((name, value))

            def end_headers(self):
                pass

        camera = {
            "id": "camera-1",
            "name": "Camera 1",
            "type": "cloud-p2p",
            "enabled": True,
        }
        prepared = {
            "id": "camera-1",
            "name": "Camera 1",
            "type": "stream",
            "url": "rtsp://127.0.0.1:12000/live",
        }
        first = FakeProcess(
            b"",
            b"[rtsp @ 0x1234] method OPTIONS failed: 503 Service Unavailable\n",
            1,
        )
        second = FakeProcess(b"\xff\xd8jpeg\xff\xd9", b"", 0)
        handler = FakeHandler()
        tunnel = FakeTunnel()

        with mock.patch.object(server, "load_config", return_value=self.config), mock.patch.object(
            server, "find_camera", return_value=camera
        ), mock.patch.object(server, "validate_camera"), mock.patch.object(
            server, "prepare_camera_input", return_value=(prepared, self.config["settings"], tunnel)
        ), mock.patch.object(
            server, "build_preview_command", return_value=["ffmpeg"]
        ), mock.patch.object(
            server.subprocess, "Popen", side_effect=[first, second]
        ) as popen, mock.patch.object(
            server.time, "sleep"
        ) as sleep, mock.patch.object(
            server, "add_log"
        ):
            server.stream_preview(handler, "camera-1")

        self.assertEqual(popen.call_count, 2)
        sleep.assert_called_once_with(server.DEFAULT_PREVIEW_RTSP_RETRY_SECONDS)
        self.assertEqual(handler.statuses, [200])
        self.assertIn(b"\xff\xd8jpeg\xff\xd9", handler.wfile.getvalue())


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
        cls.recording_relative = "Camera_1/2026-07-20/Camera_1_20260720_010000.mkv"
        recording = cls.root / "recordings" / cls.recording_relative
        recording.parent.mkdir(parents=True, exist_ok=True)
        recording.write_bytes(b"0123456789")
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

    def test_recording_catalog_and_download_support_ranges(self):
        status, _headers, body = self.request("GET", "/api/recordings")
        self.assertEqual(status, 200)
        catalog = json.loads(body)
        self.assertEqual(catalog["selectedDate"], "2026-07-20")
        self.assertEqual(catalog["selectedCamera"], "Camera_1")
        self.assertEqual(catalog["recordings"][0]["relativePath"], self.recording_relative)

        encoded = quote(self.recording_relative, safe="")
        status, headers, body = self.request("GET", f"/api/recordings/download?path={encoded}")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"0123456789")
        self.assertEqual(headers.get("Accept-Ranges"), "bytes")
        self.assertIn("attachment", headers.get("Content-Disposition", ""))

        status, headers, body = self.request(
            "GET",
            f"/api/recordings/download?path={encoded}",
            headers={"Range": "bytes=2-5"},
        )
        self.assertEqual(status, 206)
        self.assertEqual(body, b"2345")
        self.assertEqual(headers.get("Content-Range"), "bytes 2-5/10")

    def test_recording_download_rejects_path_traversal(self):
        status, _headers, body = self.request(
            "GET",
            "/api/recordings/download?path=..%2Foutside.mkv",
        )
        self.assertEqual(status, 404)
        self.assertIn("nao encontrada", body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
