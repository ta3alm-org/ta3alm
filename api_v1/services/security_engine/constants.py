"""api_v1.services.security_engine.constants
Extracted from api_v1/security_engine.py.
"""
from __future__ import annotations


# أجزاء مقسمة ومقنّعة متطابقة رياضياً مع تطبيق Flutter (RequestSigner) لتجنب تخزين المفتاح كنص صريح واحد
_SHARD_A = (0x53, 0x62, 0x2F, 0x7A, 0x41, 0x19, 0x6E, 0x33)


_SHARD_B = (0x74, 0x31, 0x6D, 0x40, 0x5F, 0x24, 0x61, 0x38)


_SHARD_C = (0x6B, 0x39, 0x50, 0x72, 0x21, 0x64, 0x48, 0x57)


_SHARD_D = (0x66, 0x33, 0x45, 0x6C, 0x2D, 0x79, 0x37, 0x4D)


_MASK_SEQ = (0x27, 0x1B, 0x4C, 0x39, 0x12, 0x55, 0x0E, 0x61)


# أرقام البناء (Build Number) بدايةً من الإصدار المزود بتوقيع الطلبات وحماية MITM الإلزامية
MIN_SIGNED_NATIVE_BUILD = 6


_HIGH_VALUE_SIGNAL_TAGS = {
    'proxy_mitm',
    'user_ca_mitm',
    'request_tamper',
    'replay_attack',
    'frida',
    'hooking',
    'integrity_tamper',
}
