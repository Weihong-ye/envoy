#!/usr/bin/env python3
"""Functional two-Envoy UDS -> UB/TCP -> UDS echo test; not a benchmark."""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time


def ip_address(host, port):
    return {"socket_address": {"address": host, "port_value": port}}


def pipe_address(path):
    return {"pipe": {"path": str(path)}}


def free_port(host):
    with socket.socket() as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def config(name, listener, upstream, admin_port):
    return {
        "admin": {"address": ip_address("127.0.0.1", admin_port)},
        "static_resources": {
            "listeners": [{
                "name": name,
                "address": listener,
                "filter_chains": [{"filters": [{
                    "name": "envoy.filters.network.tcp_proxy",
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy",
                        "stat_prefix": name,
                        "cluster": "echo",
                    },
                }]}],
            }],
            "clusters": [{
                "name": "echo",
                "type": "STATIC",
                "connect_timeout": "5s",
                "load_assignment": {
                    "cluster_name": "echo",
                    "endpoints": [{"lb_endpoints": [{"endpoint": {"address": upstream}}]}],
                },
            }],
        },
    }


def wait_ready(process, port, log_path):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Envoy exited with {process.returncode}; see {log_path}")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
        try:
            connection.request("GET", "/ready")
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                return
        except OSError:
            pass
        finally:
            connection.close()
        time.sleep(0.05)
    raise RuntimeError(f"Envoy did not become ready; see {log_path}")


def echo_backend(listener, stop):
    listener.settimeout(0.1)
    while not stop.is_set():
        try:
            connection, _ = listener.accept()
        except socket.timeout:
            continue
        with connection:
            connection.settimeout(0.1)
            while not stop.is_set():
                try:
                    data = connection.recv(65536)
                    if not data:
                        break
                    connection.sendall(data)
                except socket.timeout:
                    continue
                except OSError:
                    break


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--envoy", required=True, type=Path)
    parser.add_argument("--preload", required=True, type=Path)
    parser.add_argument("--mode", choices=("ub", "tcp"), default="ub")
    parser.add_argument("--ub-ip", default="127.0.0.2")
    parser.add_argument("--out-device", default="udmac0d1e2")
    parser.add_argument("--in-device", default="udmac0d1e2")
    parser.add_argument("--out-eid-index", type=int, default=1)
    parser.add_argument("--in-eid-index", type=int, default=1)
    parser.add_argument("--handshake-mode", choices=("tfo", "ub_sock_opt"), default="ub_sock_opt")
    parser.add_argument("--epoll-handle-mode", type=int, choices=(0, 1), default=0)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--artifact-dir", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    if args.workers < 1 or args.ub_ip == "127.0.0.1":
        parser.error("workers must be positive; use a UB IP different from the admin IP 127.0.0.1")
    if min(args.out_eid_index, args.in_eid_index) < 0:
        parser.error("EID indices must be nonnegative")
    return args


def envoy_environment(args, device, eid_index):
    environment = os.environ.copy()
    environment.update({
        "LD_PRELOAD": str(args.preload.resolve()),
        "UBSOCKET_TRANS_MODE": args.mode,
        "UBSOCKET_UB_DEV": device,
        "UBSOCKET_UB_EID_IDX": str(eid_index),
        "UBSOCKET_UB_HANDSHAKE_MODE": args.handshake_mode,
        "UBSOCKET_EPOLL_HANDLE_MODE": str(args.epoll_handle_mode),
        "UBSOCKET_UB_BUSY_POLLING": "0",
        "UBSOCKET_UB_BOUNDING_DEV": "0",
        "UBSOCKET_MONITOR_ENABLE": "false",
        "UBSOCKET_SPLIT_TRACE_ENABLE": "false",
        "UBSOCKET_CLI_ENABLE": "false",
        "UBSOCKET_PROBE_ENABLE": "false",
        "UBSOCKET_DEGRADE_ENABLE": "false",
        "KITEX_PROBE_DISABLE": "1",
        "ENVOY_UB_EXTRA_IPS": args.ub_ip,
    })
    return environment


def main():
    args = parse_args()
    envoy = args.envoy.resolve(strict=True)
    preload = args.preload.resolve(strict=True)
    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact = Path(tempfile.mkdtemp(prefix="envoy-v2-", dir=args.artifact_dir.resolve()))
    print(f"Artifacts: {artifact}", flush=True)
    # Keep AF_UNIX paths short even when the artifact directory is deeply nested.
    with tempfile.TemporaryDirectory(prefix="ubv2-", dir="/tmp") as runtime_dir:
        runtime = Path(runtime_dir)
        frontend = runtime / "front.sock"
        backend_path = runtime / "echo.sock"
        ub_port = free_port(args.ub_ip)
        admin_in = free_port("127.0.0.1")
        admin_out = free_port("127.0.0.1")
        configs = [
            ("in", config("in", ip_address(args.ub_ip, ub_port), pipe_address(backend_path), admin_in),
             admin_in, args.in_device, args.in_eid_index),
            ("out", config("out", pipe_address(frontend), ip_address(args.ub_ip, ub_port), admin_out),
             admin_out, args.out_device, args.out_eid_index),
        ]
        processes = []
        logs = []
        results = []
        stop = threading.Event()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as backend:
            backend.bind(str(backend_path))
            backend.listen(32)
            worker = threading.Thread(target=echo_backend, args=(backend, stop))
            worker.start()
            try:
                for name, document, admin, device, eid_index in configs:
                    config_path = artifact / f"{name}.json"
                    config_path.write_text(json.dumps(document, indent=2), encoding="utf-8")
                    environment = envoy_environment(args, device, eid_index)
                    log_path = artifact / f"{name}.log"
                    log = log_path.open("wb")
                    logs.append(log)
                    process = subprocess.Popen(
                        [str(envoy), "--disable-hot-restart", "--concurrency", str(args.workers),
                         "-c", str(config_path), "-l", "info"],
                        env=environment, stdout=log, stderr=subprocess.STDOUT)
                    processes.append(process)
                    wait_ready(process, admin, log_path)
                for round_number in range(3):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                        client.settimeout(10)
                        client.connect(str(frontend))
                        for length in (1, 127, 4096, 65503, 65504, 65535, 65536, 65537, 131072, 262144):
                            payload = bytes((index + round_number) % 251 for index in range(length))
                            client.sendall(payload)
                            response = bytearray()
                            while len(response) < length:
                                part = client.recv(min(65536, length - len(response)))
                                if not part:
                                    raise RuntimeError("Unexpected EOF before the complete echo")
                                response.extend(part)
                            if response != payload:
                                raise RuntimeError(f"Byte mismatch: round={round_number}, length={length}")
                            results.append({"round": round_number, "length": length,
                                            "sha256": hashlib.sha256(response).hexdigest()})
                            print(f"PASS {args.mode} round={round_number} bytes={length}", flush=True)
                for admin in (admin_in, admin_out):
                    connection = http.client.HTTPConnection("127.0.0.1", admin, timeout=2)
                    connection.request("GET", "/stats?filter=upstream_cx")
                    response = connection.getresponse()
                    if response.status != 200:
                        raise RuntimeError("Admin compatibility check failed")
                    (artifact / f"stats-{admin}.txt").write_bytes(response.read())
                    connection.close()
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.send_signal(signal.SIGTERM)
                clean_shutdown = True
                for process in reversed(processes):
                    try:
                        code = process.wait(timeout=10)
                        clean_shutdown = clean_shutdown and code == 0
                    except subprocess.TimeoutExpired:
                        clean_shutdown = False
                        process.kill()
                        process.wait()
                stop.set()
                worker.join(timeout=2)
                for log in logs:
                    log.close()
                (artifact / "result.json").write_text(json.dumps({
                    "mode": args.mode, "workers": args.workers, "cases": results,
                    "clean_shutdown": clean_shutdown,
                    "envoy": str(envoy), "preload": str(preload),
                    "ub_settings": {
                        "out_device": args.out_device, "in_device": args.in_device,
                        "out_eid_index": args.out_eid_index, "in_eid_index": args.in_eid_index,
                        "handshake_mode": args.handshake_mode,
                        "epoll_handle_mode": args.epoll_handle_mode,
                        "busy_polling": 0, "bounding_dev": 0,
                    },
                }, indent=2), encoding="utf-8")
            if not clean_shutdown:
                raise RuntimeError("Envoy did not exit cleanly; inspect logs")
    print(f"PASS: {len(results)} echo cases, reconnects, admin and clean shutdown ({args.mode})")


if __name__ == "__main__":
    main()
