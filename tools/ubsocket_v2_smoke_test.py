#!/usr/bin/env python3
"""Configuration-only tests; no Envoy, driver, or network is needed."""

import os
import unittest
from unittest import mock

import ubsocket_v2_smoke as smoke


class SmokeConfigurationTest(unittest.TestCase):
    def args(self, *extra):
        return smoke.parse_args(["--envoy", "envoy-static", "--preload", "libubsocket_preload.so",
                                 *extra])

    def test_user_baseline(self):
        args = self.args()
        env = smoke.envoy_environment(args, args.out_device, args.out_eid_index)
        self.assertEqual("1", env["UBSOCKET_UB_EID_IDX"])
        self.assertEqual("0", env["UBSOCKET_EPOLL_HANDLE_MODE"])
        self.assertEqual("ub_sock_opt", env["UBSOCKET_UB_HANDSHAKE_MODE"])
        self.assertEqual("0", env["UBSOCKET_UB_BUSY_POLLING"])
        self.assertEqual("0", env["UBSOCKET_UB_BOUNDING_DEV"])
        self.assertEqual("false", env["UBSOCKET_DEGRADE_ENABLE"])
        self.assertEqual(args.ub_ip, env["ENVOY_UB_EXTRA_IPS"])

    def test_per_side_selection(self):
        args = self.args("--out-eid-index", "2", "--in-eid-index", "3",
                         "--out-device", "out_dev", "--in-device", "in_dev")
        for device, eid in ((args.out_device, args.out_eid_index),
                            (args.in_device, args.in_eid_index)):
            env = smoke.envoy_environment(args, device, eid)
            self.assertEqual(device, env["UBSOCKET_UB_DEV"])
            self.assertEqual(str(eid), env["UBSOCKET_UB_EID_IDX"])

    def test_explicit_diagnostic_options(self):
        args = self.args("--handshake-mode", "tfo", "--epoll-handle-mode", "1")
        env = smoke.envoy_environment(args, "dev", 0)
        self.assertEqual("tfo", env["UBSOCKET_UB_HANDSHAKE_MODE"])
        self.assertEqual("1", env["UBSOCKET_EPOLL_HANDLE_MODE"])

    def test_parent_environment_is_not_modified(self):
        with mock.patch.dict(os.environ, {"UBSOCKET_UB_EID_IDX": "9",
                                         "LD_PRELOAD": "old-v1.so"}):
            before = dict(os.environ)
            env = smoke.envoy_environment(self.args(), "dev", 1)
            self.assertEqual(before, dict(os.environ))
            self.assertNotIn("old-v1.so", env["LD_PRELOAD"])

    def test_invalid_eid_is_rejected(self):
        with mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                self.args("--in-eid-index", "-1")


if __name__ == "__main__":
    unittest.main()
