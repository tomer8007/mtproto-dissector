#!/usr/bin/env python3
# Requires: frida (pip install frida)
#
# This script reads hook_script.js (same folder), waits for the telegram process,
# attaches and injects the JS.

import frida
import time
import sys
import signal
import os
import json

script_directory = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_directory)

# ===== Configuration =====
JS_FILENAME = "hook_script_android.js"   # JS file (must be in same folder or give full path)
DEFAULT_TELEGRAM_PKGS = [
    "org.telegram.messenger",
    "org.telegram.messenger.beta",
    "org.telegram.messenger.web",
]
# =========================


def main():
    print("[+] Hello")
    hook_android_process()

def hook_android_process():
    print("[+] We will hook the Android telegram app to find the auth_key.")

    process_names_to_look = DEFAULT_TELEGRAM_PKGS

    try:
        # TODO: support localhost with "adb forward tcp:27042 tcp:27042"
        device = frida.get_usb_device(timeout=10)
    except Exception as e:
        print("[!!] Could not get USB device:", e)
        print("    - Is adb running and device visible via `adb devices`?")
        sys.exit(1)

    print("[+] Waiting for " + process_names_to_look[0] + " to start.")
    pid = wait_for_process(device, process_names_to_look)

    print(f"[*] Attaching to PID " + str(pid) + ")")
    try:
        session = device.attach(pid)
    except frida.InvalidOperationError as e:
        print("[!!] Attach failed — target may not be debuggable or device not rooted.")
        print("    Error:", e)
        sys.exit(1)
    except Exception as e:
        print("[!!] Unexpected attach error:", e)
        sys.exit(1)

    try:
        with open(JS_FILENAME, "r") as f:
            js_code = f.read()
        script = session.create_script(js_code)
        script.on("message", on_message)
        script.load()
        print("[+] JS is loaded (CTRL-C to quit).")
    except Exception as e:
        print("[!!] Failed to create/load script:", e)
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


def wait_for_process(device, proc_names, poll_interval=1.0):
    print("[+] Waiting for process '{}' to start...".format(proc_names[0]))
    while True:
        try:
            procs = device.enumerate_processes()
        except Exception as e:
            print("Failed to enumerate processes:", e)
            time.sleep(poll_interval)
            continue
        for p in procs:
            for telegram_process_name in proc_names:
                if p.name.lower() == telegram_process_name.lower():
                    print("[+] Found process '{}' (pid={})".format(p.name, p.pid))
                    return p.pid
        time.sleep(poll_interval)

if __name__ == "__main__":
    main()
