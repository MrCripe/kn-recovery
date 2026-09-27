#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тесты kn-recovery. Роутер не нужен: TFTP-обмен проверяется по loopback.

Запуск:  python3 tests/test_kn_recovery.py
"""

import importlib.machinery
import importlib.util
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(os.path.dirname(HERE), "kn-recovery")


def load_tool():
    loader = importlib.machinery.SourceFileLoader("kn_recovery", TOOL)
    spec = importlib.util.spec_from_loader("kn_recovery", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


kr = load_tool()


# --------------------------------------------------------------- вспомогательное


def make_firmware(path, model="KN-1221", body_size=1_200_000, flags=0x00801221,
                  bad_crc=False, bad_magic=False):
    """Собрать синтетический образ с настоящим трейлером ZNBG."""
    body = bytes((i * 7 + 11) & 0xFF for i in range(body_size))
    trailer = bytearray(0x3C)
    trailer[0:4] = b"XXXX" if bad_magic else b"ZNBG"
    struct.pack_into("<I", trailer, 4, flags)
    name = model.encode() + b"\0"
    trailer[8:8 + len(name)] = name
    crc = (~zlib.crc32(body)) & 0xFFFFFFFF
    if bad_crc:
        crc ^= 0xFFFFFFFF
    struct.pack_into("<I", trailer, 0x38, crc)
    with open(path, "wb") as fh:
        fh.write(body + bytes(trailer))
    return path


class TftpClient:
    """Минимальный TFTP-клиент для проверки сервера."""

    def __init__(self, server_ip="127.0.0.1", server_port=69, timeout=2.0):
        self.addr = (server_ip, server_port)
        self.timeout = timeout

    def request(self, filename, mode="octet"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        pkt = struct.pack("!H", kr.OP_RRQ) + filename.encode() + b"\0" \
            + mode.encode() + b"\0"
        sock.sendto(pkt, self.addr)
        return sock

    def download(self, filename):
        sock = self.request(filename)
        received = bytearray()
        expected = 1
        try:
            while True:
                data, peer = sock.recvfrom(65535)
                opcode = struct.unpack_from("!H", data, 0)[0]
                if opcode == kr.OP_ERROR:
                    code, msg = kr.parse_error(data)
                    raise AssertionError("сервер вернул ошибку %d: %s" % (code, msg))
                if opcode != kr.OP_DATA:
                    raise AssertionError("неожиданный opcode %d" % opcode)
                block = struct.unpack_from("!H", data, 2)[0]
                if block != expected:
                    raise AssertionError("блок %d вместо %d" % (block, expected))
                chunk = data[4:]
                received.extend(chunk)
                sock.sendto(struct.pack("!HH", kr.OP_ACK, block), peer)
                if len(chunk) < 512:
                    break
                expected += 1
        finally:
            sock.close()
        return bytes(received)


# --------------------------------------------------------------------- тесты


class TestFirmwareParsing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_image(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"))
        fw = kr.Firmware.load(path)
        self.assertEqual(fw.model, "KN-1221")
        self.assertTrue(fw.crc_ok)
        self.assertEqual(fw.flags, 0x00801221)
        self.assertIn("KN-1221_recovery.bin", fw.expected_names())

    def test_other_model(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"), model="KN-1811")
        fw = kr.Firmware.load(path)
        self.assertEqual(fw.model, "KN-1811")
        self.assertIn("KN-1811_recovery.bin", fw.expected_names())

    def test_crc_mismatch_is_detected(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"), bad_crc=True)
        fw = kr.Firmware.load(path)
        self.assertFalse(fw.crc_ok)

    def test_missing_magic_rejected(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"), bad_magic=True)
        with self.assertRaises(kr.FirmwareError):
            kr.Firmware.load(path)

    def test_too_small_rejected(self):
        path = os.path.join(self.dir, "small.bin")
        with open(path, "wb") as fh:
            fh.write(b"not a firmware")
        with self.assertRaises(kr.FirmwareError):
            kr.Firmware.load(path)

    def test_missing_file_rejected(self):
        with self.assertRaises(kr.FirmwareError):
            kr.Firmware.load(os.path.join(self.dir, "нет-такого.bin"))

    def test_name_matching(self):
        path = make_firmware(os.path.join(self.dir, "KN-1221_recovery.bin"))
        fw = kr.Firmware.load(path)
        self.assertTrue(fw.matches_name("KN-1221_recovery.bin"))
        self.assertTrue(fw.matches_name("KN-1221.bin"))
        self.assertFalse(fw.matches_name("KN-1811_recovery.bin"))


class TestPacketParsing(unittest.TestCase):
    def test_rrq_without_options(self):
        pkt = struct.pack("!H", kr.OP_RRQ) + b"KN-1221_recovery.bin\0octet\0"
        op, name, mode, opts = kr.parse_request(pkt)
        self.assertEqual(op, kr.OP_RRQ)
        self.assertEqual(name, "KN-1221_recovery.bin")
        self.assertEqual(mode, "octet")
        self.assertEqual(opts, {})

    def test_rrq_with_options(self):
        pkt = (struct.pack("!H", kr.OP_RRQ)
               + b"fw.bin\x00octet\x00blksize\x00512\x00tsize\x000\x00")
        op, name, mode, opts = kr.parse_request(pkt)
        self.assertEqual(opts, {"blksize": "512", "tsize": "0"})

    def test_wrq_recognised(self):
        pkt = struct.pack("!H", kr.OP_WRQ) + b"x\0octet\0"
        op, _, _, _ = kr.parse_request(pkt)
        self.assertEqual(op, kr.OP_WRQ)

    def test_garbage_rejected(self):
        with self.assertRaises(ValueError):
            kr.parse_request(b"\x00")
        with self.assertRaises(ValueError):
            kr.parse_request(struct.pack("!H", kr.OP_ACK) + b"\x00\x01")

    def test_error_packet_roundtrip(self):
        pkt = kr.error_packet(1, "нет файла")
        code, msg = kr.parse_error(pkt)
        self.assertEqual(code, 1)
        self.assertEqual(msg, "нет файла")


class TestTransferOverLoopback(unittest.TestCase):
    """Полная передача без роутера: сервер и клиент на 127.0.0.1."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name
        self.port = self._free_port()

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _free_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _serve(self, firmware, **kw):
        server = kr.TFTPServer(
            firmware, bind_ip="127.0.0.1", port=self.port,
            expect_peer=None, log=kr.Log(quiet=True), **kw
        )
        result = {}
        thread = threading.Thread(
            target=lambda: result.update(report=server.run(max_wait=10)),
            daemon=True,
        )
        thread.start()
        time.sleep(0.3)  # дать серверу занять порт
        return server, result, thread

    def test_full_transfer_matches_source(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"), body_size=1_200_000)
        fw = kr.Firmware.load(path)
        _, result, thread = self._serve(fw)

        got = TftpClient(server_port=self.port).download("KN-1221_recovery.bin")
        thread.join(timeout=5)

        self.assertEqual(got, fw.data, "полученный файл отличается от исходного")
        report = result.get("report")
        self.assertIsNotNone(report, "сервер не вернул отчёт")
        self.assertTrue(report["served"])
        self.assertEqual(report["bytes"], len(fw.data))
        self.assertEqual(report["filename"], "KN-1221_recovery.bin")
        self.assertTrue(report["name_matches"])

    def test_transfer_size_not_multiple_of_block(self):
        # 1024 байта тела + 60 байт трейлера = 1084, не кратно 512
        path = make_firmware(os.path.join(self.dir, "fw.bin"), body_size=1024 * 1024)
        fw = kr.Firmware.load(path)
        self.assertNotEqual(len(fw.data) % 512, 0)
        _, result, thread = self._serve(fw)
        got = TftpClient(server_port=self.port).download("fw.bin")
        thread.join(timeout=5)
        self.assertEqual(got, fw.data)

    def test_wrong_name_still_served_but_flagged(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"), model="KN-1221")
        fw = kr.Firmware.load(path)
        _, result, thread = self._serve(fw)
        got = TftpClient(server_port=self.port).download("KN-9999_recovery.bin")
        thread.join(timeout=5)
        report = result["report"]
        self.assertFalse(report["name_matches"])
        self.assertTrue(report["served"])
        self.assertEqual(got, fw.data)

    def test_detect_only_does_not_transfer(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"))
        fw = kr.Firmware.load(path)
        _, result, thread = self._serve(fw, serve=False)

        sock = TftpClient(server_port=self.port).request("KN-1221_recovery.bin")
        time.sleep(0.5)
        sock.close()
        thread.join(timeout=5)

        report = result["report"]
        self.assertIsNotNone(report)
        self.assertFalse(report["served"])
        self.assertEqual(report["filename"], "KN-1221_recovery.bin")

    def test_wrq_is_refused(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"))
        fw = kr.Firmware.load(path)
        _, result, thread = self._serve(fw)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        pkt = struct.pack("!H", kr.OP_WRQ) + b"x\0octet\0"
        sock.sendto(pkt, ("127.0.0.1", self.port))
        data, _ = sock.recvfrom(1024)
        sock.close()
        thread.join(timeout=5)

        opcode = struct.unpack_from("!H", data, 0)[0]
        self.assertEqual(opcode, kr.OP_ERROR)
        code, _ = kr.parse_error(data)
        self.assertEqual(code, 2)
        self.assertFalse(result["report"]["served"])

    def test_retransmit_on_lost_ack(self):
        """Потеря ACK: клиент молчит на первый блок, сервер шлёт его снова."""
        path = make_firmware(os.path.join(self.dir, "fw.bin"), body_size=1_100_000)
        fw = kr.Firmware.load(path)
        _, result, thread = self._serve(fw, timeout=0.4, retries=4)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(struct.pack("!H", kr.OP_RRQ) + b"fw.bin\0octet\0",
                    ("127.0.0.1", self.port))

        first, peer = sock.recvfrom(65535)
        block1 = struct.unpack_from("!H", first, 2)[0]
        self.assertEqual(block1, 1)
        # Намеренно не подтверждаем и ждём повтор
        again, _ = sock.recvfrom(65535)
        self.assertEqual(struct.unpack_from("!H", again, 2)[0], 1)
        self.assertEqual(again, first, "повтор должен совпадать с первым блоком")

        # Дальше подтверждаем нормально и добираем файл
        received = bytearray()
        expected = 1
        pending = again
        while True:
            chunk = pending[4:]
            received.extend(chunk)
            sock.sendto(struct.pack("!HH", kr.OP_ACK, expected), peer)
            if len(chunk) < 512:
                break
            expected += 1
            pending, peer = sock.recvfrom(65535)
        sock.close()
        thread.join(timeout=5)
        self.assertEqual(bytes(received), fw.data)

    def test_error_from_client_aborts(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"))
        fw = kr.Firmware.load(path)
        _, result, thread = self._serve(fw, timeout=0.4, retries=2)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        sock.sendto(struct.pack("!H", kr.OP_RRQ) + b"fw.bin\0octet\0",
                    ("127.0.0.1", self.port))
        _, peer = sock.recvfrom(65535)
        sock.sendto(kr.error_packet(3, "нет места"), peer)
        time.sleep(0.6)
        sock.close()
        thread.join(timeout=5)

        report = result["report"]
        self.assertFalse(report["served"])
        self.assertIn("error", report)

    def test_ignore_unrelated_traffic(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"))
        fw = kr.Firmware.load(path)
        server, result, thread = self._serve(fw)

        # Мусорные пакеты не должны ломать сервер
        junk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for payload in (b"", b"\x00", b"\xff\xff\xff", os.urandom(20)):
            junk.sendto(payload, ("127.0.0.1", self.port))
        time.sleep(0.3)
        junk.close()

        self.assertIsNone(result.get("report"), "мусор не должен считаться запросом")
        got = TftpClient(server_port=self.port).download("fw.bin")
        thread.join(timeout=5)
        self.assertEqual(got, fw.data)

    def test_stop_interrupts_waiting(self):
        path = make_firmware(os.path.join(self.dir, "fw.bin"))
        fw = kr.Firmware.load(path)
        server, result, thread = self._serve(fw)
        time.sleep(0.3)
        server.stop()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive(), "сервер не остановился")
        self.assertIsNone(result.get("report"))


class TestHelpers(unittest.TestCase):
    def test_human_size(self):
        self.assertEqual(kr.human_size(512), "512 Б")
        self.assertEqual(kr.human_size(2048), "2.0 КиБ")
        self.assertTrue(kr.human_size(6094908).endswith("МиБ"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
