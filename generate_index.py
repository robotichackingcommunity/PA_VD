#!/usr/bin/env python3
"""Backward-compatible shim: index generation now lives in the faultline package.

    python3 -m faultline index
"""
import sys

from faultline.cli import main

sys.exit(main(["index"]))
