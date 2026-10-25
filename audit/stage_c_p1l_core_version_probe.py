#!/usr/bin/env python3
"""Read-only Windows process-image version probe. Never opens private configs.

Uses Windows PROCESS_QUERY_LIMITED_INFORMATION to find the executable image
for an explicitly supplied PID. Only verifies the basename and runs `version`
for xray.exe; no ports, proxy changes, routes or WireGuard actions occur.
"""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def query_process_image(pid: int):
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    k.OpenProcess.argtypes=(wintypes.DWORD,wintypes.BOOL,wintypes.DWORD)
    k.OpenProcess.restype=wintypes.HANDLE
    k.QueryFullProcessImageNameW.argtypes=(wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD))
    k.QueryFullProcessImageNameW.restype=wintypes.BOOL
    k.CloseHandle.argtypes=(wintypes.HANDLE,)
    h=k.OpenProcess(0x1000,False,pid)
    if not h:
        raise OSError(ctypes.get_last_error(),"IMAGE_QUERY_NOT_AUTHORIZED")
    try:
        buf=ctypes.create_unicode_buffer(32768)
        size=wintypes.DWORD(len(buf))
        if not k.QueryFullProcessImageNameW(h,0,buf,ctypes.byref(size)):
            raise OSError(ctypes.get_last_error(),"IMAGE_QUERY_FAILED")
        return Path(buf.value)
    finally:
        k.CloseHandle(h)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--pid",type=int,required=True)
    p.add_argument("--core",choices=("xray",),default="xray")
    a=p.parse_args()
    report={"probe":"P1L_CORE_READ_ONLY", "pid":a.pid,
            "core":a.core,"networkMutationsPerformed":False,
            "coreVersionVerified":False}
    if os.name!="nt":
        report["status"]="WINDOWS_ONLY"
        print(json.dumps(report,ensure_ascii=False))
        return 3
    try:
        path=query_process_image(a.pid)
        if path.name.casefold()!=a.core+".exe":
            report["status"]="WRONG_PROCESS_IMAGE"
            print(json.dumps(report,ensure_ascii=False))
            return 4
        report["fileExists"]=path.is_file()
        if not path.is_file():
            raise FileNotFoundError("IMAGE_FILE_NOT_FOUND")
        # An image's own `version` command is a safe, bounded no-config read.
        proc=subprocess.run([str(path),"version"],capture_output=True,text=True,
                            timeout=12,creationflags=0x08000000)
        # Never expose process path or commandline arguments / secrets.
        out=(proc.stdout+" "+proc.stderr)[:1600]
        match=re.search(r"(?i)\bXray\s+(?:Core\s+)?(?:v)?(\d+\.\d+(?:\.\d+)?)",out)
        report["status"]="VERSION_READ" if proc.returncode==0 else "VERSION_COMMAND_FAILED"
        report["version"]=(match.group(1) if match else None)
        report["coreVersionVerified"]=bool(report["version"] and proc.returncode==0)
        report["versionCommandExit"]=proc.returncode
    except Exception as exc:
        report["status"]="BLOCKED_READONLY"
        report["reasonCode"]=type(exc).__name__
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
    return 0 if report["coreVersionVerified"] else 2

if __name__=="__main__":
    sys.exit(main())
