#!/usr/bin/env python3
"""Regression checks for the native TCX observation ABI used by load tests."""
import ctypes
import os
import platform
import socket
import unittest

from load import BpfProgQuery, INTERFACE, tcx_program_count


class QueryTests(unittest.TestCase):
    def test_query_includes_kernel_revision_output(self):
        self.assertEqual(ctypes.sizeof(BpfProgQuery), 64)
        self.assertEqual(BpfProgQuery.revision.offset, 56)
        self.assertEqual(BpfProgQuery.prog_cnt.offset, 24)

    @unittest.skipUnless(os.geteuid() == 0, 'requires root and the running LXC lab')
    def test_repeated_kernel_queries_preserve_guard_bytes(self):
        if tcx_program_count(INTERFACE) is None:
            self.skipTest('TCX unavailable; lab:load observes legacy TC filters instead')
        class GuardedQuery(ctypes.Structure):
            _fields_ = [('query', BpfProgQuery), ('guard', ctypes.c_ubyte * 64)]

        number = {'aarch64': 280, 'x86_64': 321}[platform.machine()]
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        for _ in range(1000):
            value = GuardedQuery(query=BpfProgQuery(
                ifindex=socket.if_nametoindex(INTERFACE), attach_type=47))
            value.guard[:] = [0xa5] * 64
            result = libc.syscall(number, 16, ctypes.byref(value.query), ctypes.sizeof(value.query))
            self.assertEqual(result, 0, os.strerror(ctypes.get_errno()))
            self.assertEqual(bytes(value.guard), b'\xa5' * 64)
            self.assertIsNotNone(tcx_program_count(INTERFACE))


if __name__ == '__main__':
    unittest.main()
