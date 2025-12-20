#!/usr/bin/env python3
# Requires: frida (pip install frida)
#
# This script reads hook_script.js (same folder), waits for Telegram.exe,
# attaches and injects the JS.

import frida
import time
import sys
import signal
import os
import json

# ===== Configuration =====
PROCESS_NAME = "Telegram.exe"    # process name to wait for (case-insensitive)
JS_FILENAME = "hook_script_windows.js"   # JS file (must be in same folder or give full path)
# =========================


def main():
    print("[+] Hello")
    hook_windows_process()

def hook_windows_process():
    print("[+] We will hook the Windows telegram app to find the auth_key.")

    try:
        device = frida.get_local_device()
    except Exception as e:
        print("Failed to get local frida device:", e)
        sys.exit(1)

    pid = wait_for_process(device, PROCESS_NAME)

    try:
        print("[+] Attaching to pid", pid)
        session = device.attach(pid)
    except frida.ProcessNotFoundError:
        print("Process went away before attach; retrying...")
        return main()
    except Exception as e:
        print("Failed to attach:", e)
        sys.exit(1)

    # Load JS
    js_path = os.path.join(os.path.dirname(__file__), JS_FILENAME)
    js_file_contents = open(js_path, "r", encoding="utf-8").read()

    try:
        script = session.create_script(js_file_contents)
        script.on("message", on_message)
        script.load()
    except Exception as e:
        print("Failed to create/load script:", e)
        session.detach()
        sys.exit(1)

    def handle_sigint(sig, frame):
        print("Detaching and exiting...")
        try:
            session.detach()
        except Exception:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handle_sigint(None, None)


def on_message(message, data):
    print(message)


def wait_for_process(device, proc_name, poll_interval=1.0):
    print("[+] Waiting for process '{}' to start...".format(proc_name))
    while True:
        try:
            procs = device.enumerate_processes()
        except Exception as e:
            print("Failed to enumerate processes:", e)
            time.sleep(poll_interval)
            continue
        for p in procs:
            if p.name.lower() == proc_name.lower():
                print("[+] Found process '{}' (pid={})".format(p.name, p.pid))
                return p.pid
        time.sleep(poll_interval)

if __name__ == "__main__":
    main()
