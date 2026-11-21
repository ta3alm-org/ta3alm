"""api_v1.services.device_security.constants
Extracted from api_v1/device_security_service.py.
"""
from __future__ import annotations


FINGERPRINT_ALGORITHM_VERSION = 'fp_v1'


MAX_IP_HISTORY_ENTRIES = 20


WEB_PACKAGE_NAME = 'web.ta3alm.online'


WEB_COOKIE_NAME = 'ta3alm_web_inst_id'


WEB_COOKIE_SALT = 'ta3alm-web-device-v1'


CORE_FINGERPRINT_FIELDS = ('manufacturer', 'model', 'cpu_arch', 'package_name')


SUPPORTING_FINGERPRINT_FIELDS = (
    'android_version',
    'api_level',
    'cpu_info',
    'gpu_renderer',
    'gpu_vendor',
    'screen_resolution',
    'app_version',
    'app_build_number',
    'signing_cert_sha256',
    'installer_source',
)


BENIGN_DRIFT_FIELDS = {
    'android_version',
    'api_level',
    'app_version',
    'app_build_number',
    'screen_resolution',
    'installer_source',
    'gpu_renderer',
    'gpu_vendor',
    'cpu_info',
}


WEB_STRICT_CORE_FIELDS = (
    'manufacturer',
    'model',
    'cpu_arch',
    'cpu_info',
    'gpu_renderer',
    'gpu_vendor',
    'web_canvas_hash',
    'web_webgl_hash',
    'web_audio_hash',
    'web_hw_sig',
    'web_max_touch_points',
    'web_color_depth',
    'web_navigator_platform',
)


_VPN_ISP_KEYWORDS = (
    'cloudflare warp',
    'm247',
    'nordvpn',
    'expressvpn',
    'protonvpn',
    'proton ag',
    'mullvad',
    'surfshark',
    'windscribe',
    'psiphon',
    'privatelayer',
    'tzulo',
    'datacamp',
    'packethub',
    'choopa',
    'vultr',
    'hetzner',
    'ovh',
    'linode',
    'digitalocean',
    'tor exit',
    'wireguard',
)


_DESKTOP_OR_EMULATED_GPU_TOKENS = (
    'direct3d',
    'd3d11',
    'd3d9',
    'nvidia',
    'geforce',
    'quadro',
    'rtx ',
    'gtx ',
    'radeon',
    'amd ',
    'amd/',
    'intel(r)',
    'intel iris',
    'uhd graphics',
    'hd graphics',
    'swiftshader',
    'mesa',
    'llvmpipe',
    'softpipe',
    'virgl',
    'vmware',
    'virtualbox',
    'google inc.',
    'angle (',
    'microsoft basic',
)


_BROWSER_UA_MARKERS = (
    'mozilla/',
    'applewebkit/',
    'chrome/',
    'safari/',
    'firefox/',
    'edg/',
    'opr/',
    'opera/',
    'crios/',
    'fxios/',
    'edgios/',
)


WEB_IOS_ONLY_ERROR = (
    'عرض وتشغيل المحاضرات عبر المتصفح متاح فقط لأجهزة iPhone و iPad (ومحظور على أجهزة Mac والكمبيوتر وأندرويد) '
    'لحماية روابط المحاضرات. يرجى استخدام تطبيق تعلّم أو متصفح iPhone/iPad رسمي.'
)
