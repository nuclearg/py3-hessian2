import datetime
import time
import unittest
from datetime import tzinfo

from hessian2 import hessian2_dumps, hessian2_loads


class Test(unittest.TestCase):
    def test_encode_null(self):
        self.assertEqual(hessian2_dumps(None), b'N')

    def test_decode_null(self):
        self.assertIsNone(hessian2_loads(b'N'))

    def test_encode_boolean(self):
        self.assertEqual(hessian2_dumps(True), b'T')
        self.assertEqual(hessian2_dumps(False), b'F')

    def test_decode_boolean(self):
        self.assertTrue(hessian2_loads(b'T'))
        self.assertFalse(hessian2_loads(b'F'))

    def test_encode_int(self):
        self.assertEqual(hessian2_dumps(0), b'\x90')
        self.assertEqual(hessian2_dumps(1), b'\x91')
        self.assertEqual(hessian2_dumps(16), b'\xa0')
        self.assertEqual(hessian2_dumps(1000), b'\xcb\xe8')
        self.assertEqual(hessian2_dumps(16000), b'\xd4\x3e\x80')
        self.assertEqual(hessian2_dumps(-65000), b'\xd3\x02\x18')
        self.assertEqual(hessian2_dumps(500000), b'\x49\x00\x07\xa1\x20')
        self.assertEqual(hessian2_dumps(80000000000), b'\x4c\x00\x00\x00\x12\xa0\x5f\x20\x00')
        self.assertEqual(hessian2_dumps(9000000000000000), b'\x4c\x00\x1f\xf9\x73\xca\xfa\x80\x00')
        self.assertEqual(hessian2_dumps(-9000000000000000000), b'\x4c\x83\x19\x93\xaf\x1d\x7c\x00\x00')
        self.assertEqual(hessian2_dumps(-0x10), b'\x80')
        self.assertEqual(hessian2_dumps(0x2f), b'\xbf')
        self.assertEqual(hessian2_dumps(-0x800), b'\xc0\x00')
        self.assertEqual(hessian2_dumps(0x7ff), b'\xcf\xff')
        self.assertEqual(hessian2_dumps(-0x40000), b'\xd0\x00\x00')
        self.assertEqual(hessian2_dumps(0x3ffff), b'\xd7\xff\xff')
        self.assertEqual(hessian2_dumps(-2147483648), b'\x49\x80\x00\x00\x00')
        self.assertEqual(hessian2_dumps(2147483647), b'\x49\x7f\xff\xff\xff')
        self.assertEqual(hessian2_dumps(-9223372036854775808), b'\x4c\x80\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(hessian2_dumps(9223372036854775807), b'\x4c\x7f\xff\xff\xff\xff\xff\xff\xff')

    def test_decode_int(self):
        self.assertEqual(hessian2_loads(b'\x90'), 0)
        self.assertEqual(hessian2_loads(b'\x91'), 1)
        self.assertEqual(hessian2_loads(b'\xa0'), 16)
        self.assertEqual(hessian2_loads(b'\xcb\xe8'), 1000)
        self.assertEqual(hessian2_loads(b'\xd4\x3e\x80'), 16000)
        self.assertEqual(hessian2_loads(b'\xd3\x02\x18'), -65000)
        self.assertEqual(hessian2_loads(b'\x49\x00\x07\xa1\x20'), 500000)
        self.assertEqual(hessian2_loads(b'\x4c\x00\x00\x00\x12\xa0\x5f\x20\x00'), 80000000000)
        self.assertEqual(hessian2_loads(b'\x4c\x00\x1f\xf9\x73\xca\xfa\x80\x00'), 9000000000000000)
        self.assertEqual(hessian2_loads(b'\x4c\x83\x19\x93\xaf\x1d\x7c\x00\x00'), -9000000000000000000)
        self.assertEqual(hessian2_loads(b'\x80'), -0x10)
        self.assertEqual(hessian2_loads(b'\xbf'), 0x2f)
        self.assertEqual(hessian2_loads(b'\xc0\x00'), -0x800)
        self.assertEqual(hessian2_loads(b'\xcf\xff'), 0x7ff)
        self.assertEqual(hessian2_loads(b'\xd0\x00\x00'), -0x40000)
        self.assertEqual(hessian2_loads(b'\xd7\xff\xff'), 0x3ffff)
        self.assertEqual(hessian2_loads(b'\x49\x80\x00\x00\x00'), -2147483648)
        self.assertEqual(hessian2_loads(b'\x49\x7f\xff\xff\xff'), 2147483647)
        self.assertEqual(hessian2_loads(b'\x4c\x80\x00\x00\x00\x00\x00\x00\x00'), -9223372036854775808)
        self.assertEqual(hessian2_loads(b'\x4c\x7f\xff\xff\xff\xff\xff\xff\xff'), 9223372036854775807)

    def test_encode_float(self):
        self.assertEqual(hessian2_dumps(0.0), b'\x5b')
        self.assertEqual(hessian2_dumps(1.0), b'\x5c')
        self.assertEqual(hessian2_dumps(3.0), b'\x5d\x03')
        self.assertEqual(hessian2_dumps(-1.0), b'\x5d\xff')
        self.assertEqual(hessian2_dumps(127.0), b'\x5d\x7f')
        self.assertEqual(hessian2_dumps(-128.0), b'\x5d\x80')
        self.assertEqual(hessian2_dumps(300.0), b'\x5e\x01\x2c')
        self.assertEqual(hessian2_dumps(10000.0), b'\x5e\x27\x10')
        self.assertEqual(hessian2_dumps(3.14), b'\x5f\x00\x00\x0c\x44')
        self.assertEqual(hessian2_dumps(3.1415926), b'\x44\x40\x09\x21\xfb\x4d\x12\xd8\x4a')

    def test_decode_float(self):
        self.assertEqual(hessian2_loads(b'\x5b'), 0.0)
        self.assertEqual(hessian2_loads(b'\x5c'), 1.0)
        self.assertEqual(hessian2_loads(b'\x5d\x03'), 3.0)
        self.assertEqual(hessian2_loads(b'\x5d\xff'), -1.0)
        self.assertEqual(hessian2_loads(b'\x5d\x80'), -128.0)
        self.assertEqual(hessian2_loads(b'\x5e\x01\x2c'), 300.0)
        self.assertEqual(hessian2_loads(b'\x5e\x27\x10'), 10000.0)
        self.assertEqual(hessian2_loads(b'\x5e\x80\x00'), -32768.0)
        self.assertAlmostEqual(hessian2_loads(b'\x5f\x00\x00\x0c\x44'), 3.14, places=6)
        self.assertAlmostEqual(hessian2_loads(b'\x44\x40\x09\x21\xfb\x4d\x12\xd8\x4a'), 3.1415926, places=7)
        self.assertAlmostEqual(hessian2_loads(b'\x44\x3f\xf1\x99\x99\x99\x99\x99\x9a'), 1.1, places=15)

    def test_encode_binary(self):
        self.assertEqual(hessian2_dumps(b''), b'\x20')
        self.assertEqual(hessian2_dumps(b'\x00'), b'\x21\x00')
        self.assertEqual(hessian2_dumps(b'\xff'), b'\x21\xff')
        self.assertEqual(hessian2_dumps(b'hello'), b'\x25\x68\x65\x6c\x6c\x6f')
        self.assertEqual(hessian2_dumps(b'a' * 15), b'\x2f' + b'\x61' * 15)
        self.assertEqual(hessian2_dumps(b'a' * 16), b'\x34\x10' + b'\x61' * 16)
        self.assertEqual(hessian2_dumps(b'a' * 127), b'\x34\x7f' + b'\x61' * 127)
        self.assertEqual(hessian2_dumps(b'a' * 128), b'\x34\x80' + b'\x61' * 128)
        self.assertEqual(hessian2_dumps(b'a' * 1023), b'\x37\xff' + b'\x61' * 1023)
        self.assertEqual(hessian2_dumps(b'a' * 1024), b'\x42\x04\x00' + b'\x61' * 1024)
        self.assertEqual(hessian2_dumps(b'a' * 4096), self._read_file('long_bytes_4096.txt'))
        self.assertEqual(hessian2_dumps(b'a' * 5000), self._read_file('long_bytes_5000.txt'))
        self.assertEqual(hessian2_dumps(b'a' * 65535), self._read_file('long_bytes_65535.txt'))

    def test_decode_binary(self):
        self.assertEqual(hessian2_loads(b'\x20'), b'')
        self.assertEqual(hessian2_loads(b'\x21\x00'), b'\x00')
        self.assertEqual(hessian2_loads(b'\x21\xff'), b'\xff')
        self.assertEqual(hessian2_loads(b'\x25\x68\x65\x6c\x6c\x6f'), b'hello')
        self.assertEqual(hessian2_loads(b'\x2f' + b'\x61' * 15), b'a' * 15)
        self.assertEqual(hessian2_loads(b'\x34\x10' + b'\x61' * 16), b'a' * 16)
        self.assertEqual(hessian2_loads(b'\x34\x7f' + b'\x61' * 127), b'a' * 127)
        self.assertEqual(hessian2_loads(b'\x34\x80' + b'\x61' * 128), b'a' * 128)
        self.assertEqual(hessian2_loads(b'\x37\xff' + b'\x61' * 1023), b'a' * 1023)
        self.assertEqual(hessian2_loads(b'\x42\x04\x00' + b'\x61' * 1024), b'a' * 1024)
        self.assertEqual(hessian2_loads(self._read_file('long_bytes_4096.txt')), b'a' * 4096)
        self.assertEqual(hessian2_loads(self._read_file('long_bytes_5000.txt')), b'a' * 5000)
        self.assertEqual(hessian2_loads(self._read_file('long_bytes_65535.txt')), b'a' * 65535)

    def test_encode_string(self):
        self.assertEqual(hessian2_dumps(''), b'\x00')
        self.assertEqual(hessian2_dumps('hello'), b'\x05\x68\x65\x6c\x6c\x6f')
        self.assertEqual(hessian2_dumps('a' * 128), b'\x30\x80' + b'\x61' * 128)
        self.assertEqual(hessian2_dumps('中文测试'), b'\x04\xe4\xb8\xad\xe6\x96\x87\xe6\xb5\x8b\xe8\xaf\x95')
        self.assertEqual(hessian2_dumps('一二三四五六七八九十一二三四五六七八九十一二三四五六七八九十一'), b'\x1f\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89\xe5\x9b\x9b\xe4\xba\x94\xe5\x85\xad\xe4\xb8\x83\xe5\x85\xab\xe4\xb9\x9d\xe5\x8d\x81\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89\xe5\x9b\x9b\xe4\xba\x94\xe5\x85\xad\xe4\xb8\x83\xe5\x85\xab\xe4\xb9\x9d\xe5\x8d\x81\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89\xe5\x9b\x9b\xe4\xba\x94\xe5\x85\xad\xe4\xb8\x83\xe5\x85\xab\xe4\xb9\x9d\xe5\x8d\x81\xe4\xb8\x80')
        self.assertEqual(hessian2_dumps('abc' * 1024), b'\x53\x0c\x00' + b'\x61\x62\x63' * 1024)
        self.assertEqual(hessian2_dumps('啊' * 32768), b'\x53\x80\x00' + b'\xe5\x95\x8a' * 32768)
        self.assertEqual(hessian2_dumps('helloworld我人有的和' * 80000), self._read_file('long_str1.txt'))
        self.assertEqual(hessian2_dumps('\x00'), b'\x01\x00')
        self.assertEqual(hessian2_dumps('\xff'), b'\x01\xc3\xbf')
        self.assertEqual(hessian2_dumps('\u00a9'), b'\x01\xc2\xa9')
        self.assertEqual(hessian2_dumps('a' * 15), b'\x0f' + b'\x61' * 15)
        self.assertEqual(hessian2_dumps('a' * 16), b'\x10' + b'\x61' * 16)
        self.assertEqual(hessian2_dumps('a' * 2048), b'\x53\x08\x00' + b'\x61' * 2048)

    def test_decode_string(self):
        self.assertEqual(hessian2_loads(b'\x00'), '')
        self.assertEqual(hessian2_loads(b'\x05\x68\x65\x6c\x6c\x6f'), 'hello')
        self.assertEqual(hessian2_loads(b'\x30\x80' + b'\x61' * 128), 'a' * 128)
        self.assertEqual(hessian2_loads(b'\x04\xe4\xb8\xad\xe6\x96\x87\xe6\xb5\x8b\xe8\xaf\x95'), '中文测试')
        self.assertEqual(hessian2_loads(b'\x1f\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89\xe5\x9b\x9b\xe4\xba\x94\xe5\x85\xad\xe4\xb8\x83\xe5\x85\xab\xe4\xb9\x9d\xe5\x8d\x81\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89\xe5\x9b\x9b\xe4\xba\x94\xe5\x85\xad\xe4\xb8\x83\xe5\x85\xab\xe4\xb9\x9d\xe5\x8d\x81\xe4\xb8\x80\xe4\xba\x8c\xe4\xb8\x89\xe5\x9b\x9b\xe4\xba\x94\xe5\x85\xad\xe4\xb8\x83\xe5\x85\xab\xe4\xb9\x9d\xe5\x8d\x81\xe4\xb8\x80'), '一二三四五六七八九十一二三四五六七八九十一二三四五六七八九十一')
        self.assertEqual(hessian2_loads(b'\x53\x0c\x00' + b'\x61\x62\x63' * 1024), 'abc' * 1024)
        self.assertEqual(hessian2_loads(b'\x53\x80\x00' + b'\xe5\x95\x8a' * 32768), '啊' * 32768)
        self.assertEqual(hessian2_loads(self._read_file('long_str1.txt')), 'helloworld我人有的和' * 80000)
        self.assertEqual(hessian2_loads(b'\x01\x00'), '\x00')
        self.assertEqual(hessian2_loads(b'\x01\xc3\xbf'), '\xff')
        self.assertEqual(hessian2_loads(b'\x01\xc2\xa9'), '\u00a9')
        self.assertEqual(hessian2_loads(b'\x0f' + b'\x61' * 15), 'a' * 15)
        self.assertEqual(hessian2_loads(b'\x10' + b'\x61' * 16), 'a' * 16)
        self.assertEqual(hessian2_loads(b'\x53\x08\x00' + b'\x61' * 2048), 'a' * 2048)

    def test_encode_date(self):
        self.assertEqual(hessian2_dumps(datetime.datetime(2021, 2, 3, 11, 22, 33)), b'\x4a\x00\x00\x01\x77\x65\xe9\xbc\xa8')

    def test_decode_date(self):
        decoded = hessian2_loads(b'\x4a\x00\x00\x01\x77\x65\xe9\xbc\xa8')
        self.assertEqual(decoded, datetime.datetime(2021, 2, 3, 11, 22, 33))

    def test_encode_list(self):
        pass

    def test_decode_list(self):
        pass

    def test_encode_map(self):
        self.assertEqual(hessian2_dumps({'a': 1, 'b': None, 'c': '3'}), b'\x48\x01\x61\x91\x01\x62\x4e\x01\x63\x01\x33\x5a')
        self.assertEqual(hessian2_dumps({1: '1', 2: '2'}), b'\x48\x91\x01\x31\x92\x01\x32\x5a')
        self.assertEqual(hessian2_dumps({1.0: '1.0', 2.2: '2.2'}), b'\x48\x5c\x03\x31\x2e\x30\x5f\x00\x00\x08\x98\x03\x32\x2e\x32\x5a')
        m = {'a': '1', 'b': '2'}
        self.assertEqual(hessian2_dumps({'m1': m, 'm2': m}), b'\x48\x02\x6d\x31\x48\x01\x61\x01\x31\x01\x62\x01\x32\x5a\x02\x6d\x32\x51\x91\x5a')
        self.assertEqual(hessian2_dumps({'a': '1', 'b': '2', '#class': 'java.util.concurrent.ConcurrentHashMap'}), b'\x4d\x30\x26\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x63\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x2e\x43\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x48\x61\x73\x68\x4d\x61\x70\x01\x61\x01\x31\x01\x62\x01\x32\x5a')

        print(hessian2_dumps({'a': 'a', 'b': 3, '#class': 'org.example.Main.TestBean'}))

    def test_decode_map(self):
        self.assertEqual(hessian2_loads(b'\x48\x01\x61\x91\x01\x62\x4e\x01\x63\x01\x33\x5a'), {'a': 1, 'b': None, 'c': '3'})
        self.assertEqual(hessian2_loads(b'\x48\x91\x01\x31\x92\x01\x32\x5a'), {1: '1', 2: '2'})
        self.assertEqual(hessian2_loads(b'\x48\x5c\x03\x31\x2e\x30\x5f\x00\x00\x08\x98\x03\x32\x2e\x32\x5a'), {1.0: '1.0', 2.2: '2.2'})
        self.assertEqual(hessian2_loads(b'\x48\x02\x6d\x31\x48\x01\x61\x01\x31\x01\x62\x01\x32\x5a\x02\x6d\x32\x51\x91\x5a'), {'m1': {'a': '1', 'b': '2'}, 'm2': {'a': '1', 'b': '2'}})

    @staticmethod
    def _read_file(filename: str) -> bytes:
        with open(filename, 'r') as f:
            return f.read().strip().encode().decode("unicode_escape").encode("latin1")
