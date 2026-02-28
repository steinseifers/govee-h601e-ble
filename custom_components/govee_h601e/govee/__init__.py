"""Govee H601E protocol sub-package.

This package is intentionally free of any Home Assistant dependencies so that
it can be unit-tested in isolation and potentially reused in other contexts.

Sub-modules
-----------
device  – Crypto primitives, frame builders, state model and protocol class.
scanner – Helper utilities for detecting H601E devices in BLE advertisement data.
"""
