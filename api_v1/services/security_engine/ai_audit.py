"""api_v1.services.security_engine.ai_audit
Extracted from api_v1/security_engine.py.
"""
from __future__ import annotations

from datetime import timedelta
import os
from typing import Any
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from api_v1.models import (
    DeviceActivity,
    DeviceSession,
    SecurityPolicyConfig,
    UserSecurityProfile,
)

from api_v1.services.security_engine.behavioral import (
    compute_behavioral_risk,
    is_protected_admin_user,
)
from api_v1.services.security_engine.enforcement import enforce_security_ban


def _mask_secret(raw: str) -> str:
    clean = str(raw or '').strip()
    if not clean or clean == 'PUT_YOUR_AI_API_KEY_HERE':
        return ''
    if len(clean) <= 10:
        return '*' * len(clean)
    return f"{clean[:4]}...{clean[-4:]}"


def get_effective_ai_config(policy: SecurityPolicyConfig | None = None) -> dict[str, Any]:
    """استخراج إعدادات الذكاء الاصطناعي الأمني مع أولوية المفتاح المُدخل من لوحة الإدارة ثم settings ثم متغيرات البيئة."""
    pol = policy or SecurityPolicyConfig.load()
    candidates = [
        getattr(pol, 'ai_api_key_override', ''),
        getattr(settings, 'AI_SECURITY_API_KEY', ''),
        os.environ.get('AI_SECURITY_API_KEY', ''),
        os.environ.get('GEMINI_API_KEY', ''),
        os.environ.get('GOOGLE_API_KEY', ''),
        os.environ.get('OPENAI_API_KEY', ''),
        os.environ.get('GROQ_API_KEY', ''),
    ]
    raw_key = next(
        (
            str(val or '').strip()
            for val in candidates
            if str(val or '').strip() and str(val or '').strip() != 'PUT_YOUR_AI_API_KEY_HERE'
        ),
        '',
    )
    is_configured = bool(raw_key and raw_key != 'PUT_YOUR_AI_API_KEY_HERE')

    provider = str(getattr(pol, 'ai_provider', '') or getattr(settings, 'AI_SECURITY_PROVIDER', 'auto') or 'auto').strip().lower()
    model = str(getattr(pol, 'ai_model_name', '') or getattr(settings, 'AI_SECURITY_MODEL', 'gemini-2.5-flash') or 'gemini-2.5-flash').strip()
    if provider == 'auto' or provider not in ('gemini', 'openai', 'groq', 'deepseek'):
        if raw_key.startswith('AIza') or raw_key.startswith('AQ.'):
            provider = 'gemini'
        elif raw_key.startswith('gsk_'):
            provider = 'groq'
        elif 'deepseek' in model.lower():
            provider = 'deepseek'
        elif raw_key.startswith('sk-'):
            provider = 'openai'
        elif 'gemini' in model.lower():
            provider = 'gemini'
        elif raw_key:
            provider = 'openai'
        else:
            provider = 'gemini'

    return {
        'enabled': bool(getattr(pol, 'ai_security_enabled', True)),
        'hourly_enabled': bool(getattr(pol, 'ai_hourly_schedule_enabled', True) and getattr(settings, 'AI_SECURITY_HOURLY_ENABLED', True)),
        'auto_enforce': bool(getattr(pol, 'ai_auto_enforce_bans', True)),
        'api_key': raw_key if is_configured else '',
        'configured': is_configured,
        'masked_key': _mask_secret(raw_key),
        'provider': provider,
        'model': model,
    }


def _extract_json_object(raw_text: str) -> dict[str, Any]:
    import json
    import re as _re

    text = str(raw_text or '').strip()
    if text.startswith('```'):
        text = _re.sub(r'^```(?:json)?\s*|\s*```$', '', text, flags=_re.IGNORECASE | _re.DOTALL).strip()
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass
    m = _re.search(r'\{.*\}', text, flags=_re.DOTALL)
    if m:
        parsed = json.loads(m.group(0))
        if isinstance(parsed, dict):
            return parsed
    raise ValueError('AI returned non-JSON security verdict')


def _call_ai_security_llm(telemetry: dict[str, Any], ai_cfg: dict[str, Any]) -> dict[str, Any]:
    """استدعاء نموذج الذكاء الاصطناعي الخارجي (Gemini / OpenAI / Groq / DeepSeek) لتحليل سلوك المستخدم."""
    import json
    import urllib.parse
    import urllib.request

    system_prompt = (
        "أنت محلل أمن سيبراني لمنصة تعليمية. قم بتحليل بيانات سلوك المستخدم وأجهزته التالية بدقة "
        "لاكتشاف محاولات الاختراق، الاعتراض (Burp/HttpCanary/MITM/Proxy)، مشاركة الحساب، التخمين، أو القرصنة. "
        "أرجع كائن JSON فقط بالحقول التالية: "
        '{"risk_score": 0-100, "risk_level": "low|medium|high|critical", '
        '"recommended_action": "none|warn|device_only|user_only|device_and_user", '
        '"target_installation_id": "", "reason_ar": "ملخص عربي واضح ومختصر للسبب"}. '
        "قواعد الحظر: استخدم device_only إذا كان العبث/MITM من جهاز معين؛ user_only إذا كان الاختراق/المشاركة من الحساب عبر عدة أجهزة؛ "
        "device_and_user للهجوم الخطير المتعمد أو تعدد الانتهاكات الحرجة؛ none أو warn للسلوك التعليمي الطبيعي."
    )
    user_prompt = json.dumps(telemetry, ensure_ascii=False)
    api_key = ai_cfg['api_key']
    provider = ai_cfg['provider']
    model = ai_cfg['model']

    if provider == 'gemini':
        safe_model = urllib.parse.quote(model or 'gemini-2.5-flash', safe='.-_')
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{safe_model}:generateContent?key={urllib.parse.quote(api_key)}"
        body = {
            'contents': [{'role': 'user', 'parts': [{'text': f"{system_prompt}\n\nالبيانات:\n{user_prompt}"}]}],
            'generationConfig': {
                'temperature': 0.1,
                'responseMimeType': 'application/json',
            },
        }
        headers = {'Content-Type': 'application/json'}
    else:
        if provider == 'groq':
            url = 'https://api.groq.com/openai/v1/chat/completions'
            default_m = 'llama-3.3-70b-versatile'
        elif provider == 'deepseek':
            url = 'https://api.deepseek.com/chat/completions'
            default_m = 'deepseek-chat'
        else:
            url = 'https://api.openai.com/v1/chat/completions'
            default_m = 'gpt-4o-mini'
        chosen_model = model if (model and not model.startswith('gemini')) else default_m
        body = {
            'model': chosen_model,
            'temperature': 0.1,
            'response_format': {'type': 'json_object'},
            'messages': [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt},
            ],
        }
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
        }

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode('utf-8'),
        headers=headers,
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw_resp = json.loads(resp.read().decode('utf-8'))

    if provider == 'gemini':
        text_out = (
            raw_resp.get('candidates', [{}])[0]
            .get('content', {})
            .get('parts', [{}])[0]
            .get('text', '')
        )
    else:
        text_out = (
            raw_resp.get('choices', [{}])[0]
            .get('message', {})
            .get('content', '')
        )
    parsed = _extract_json_object(text_out)
    score = min(max(int(parsed.get('risk_score') or 0), 0), 100)
    action = str(parsed.get('recommended_action') or 'none').strip()
    if action not in ('none', 'warn', 'device_only', 'user_only', 'device_and_user'):
        action = 'warn' if score >= 60 else 'none'
    level = str(parsed.get('risk_level') or '').strip()
    if level not in ('low', 'medium', 'high', 'critical'):
        level = 'critical' if score >= 85 else ('high' if score >= 60 else ('medium' if score >= 30 else 'low'))
    return {
        'used_external_ai': True,
        'risk_score': score,
        'risk_level': level,
        'recommended_action': action,
        'target_installation_id': str(parsed.get('target_installation_id') or '').strip(),
        'reason_ar': str(parsed.get('reason_ar') or '').strip()[:600],
    }


def analyze_user_with_ai(
    user,
    *,
    enforce_if_flagged: bool = True,
    request=None,
) -> dict[str, Any]:
    """
    تشغيل تحليل الذكاء الاصطناعي للمستخدم بناءً على حركات اليوم وسجله،
    مع حفظ القرار وتنفيذ الحظر الانتقائي/المشترك تلقائياً عند وجود خطورة عالية.
    """
    from api_v1.selectors.security_selectors import collect_user_today_telemetry
    policy = SecurityPolicyConfig.load()
    ai_cfg = get_effective_ai_config(policy)
    heur = compute_behavioral_risk(user)
    profile: UserSecurityProfile = heur['profile']
    telemetry = collect_user_today_telemetry(user)

    verdict: dict[str, Any]
    if ai_cfg['enabled'] and ai_cfg['configured']:
        try:
            verdict = _call_ai_security_llm(telemetry, ai_cfg)
        except Exception as exc:
            reason_bits = '، '.join(heur['reasons'][:4]) if heur['reasons'] else 'نشاط طبيعي دون مؤشرات عبث'
            verdict = {
                'used_external_ai': False,
                'risk_score': heur['score'],
                'risk_level': heur['level'],
                'recommended_action': _derive_heuristic_action(heur['score'], heur['reasons'], telemetry),
                'target_installation_id': _pick_riskiest_installation_id(telemetry),
                'reason_ar': f"تحليل سلوكي محلي ({reason_bits}) — تعذر الاتصال بـ AI الخارجي: {str(exc)[:100]}",
            }
    else:
        heur_action = _derive_heuristic_action(heur['score'], heur['reasons'], telemetry)
        reason_bits = '، '.join(heur['reasons'][:4]) if heur['reasons'] else 'نشاط طبيعي دون مؤشرات عبث'
        verdict = {
            'used_external_ai': False,
            'risk_score': heur['score'],
            'risk_level': heur['level'],
            'recommended_action': heur_action,
            'target_installation_id': _pick_riskiest_installation_id(telemetry),
            'reason_ar': f"تحليل سلوكي ذكي ({reason_bits}) — ضع مفتاح AI API لتفعيل التحليل بالذكاء الاصطناعي التوليدي.",
        }

    now = timezone.now()
    profile.ai_risk_score = verdict['risk_score']
    profile.ai_recommended_action = verdict['recommended_action']
    profile.ai_analysis_summary = verdict['reason_ar']
    profile.ai_last_analyzed_at = now
    if verdict['risk_score'] > profile.behavior_risk_score:
        profile.behavior_risk_score = verdict['risk_score']
        profile.behavior_risk_level = verdict['risk_level']
    profile.save(
        update_fields=[
            'ai_risk_score',
            'ai_recommended_action',
            'ai_analysis_summary',
            'ai_last_analyzed_at',
            'behavior_risk_score',
            'behavior_risk_level',
            'analyzed_at',
        ]
    )

    enforcement_res = None
    rec_action = verdict['recommended_action']
    if (
        enforce_if_flagged
        and policy.ai_auto_enforce_bans
        and not is_protected_admin_user(user)
        and rec_action in ('device_only', 'user_only', 'device_and_user')
        and (verdict['risk_score'] >= policy.risk_threshold_critical or telemetry['proxy_tamper_strikes'] > 0)
    ):
        target_inst = verdict.get('target_installation_id') or _pick_riskiest_installation_id(telemetry)
        enforcement_res = enforce_security_ban(
            user=user,
            installation_id=target_inst if rec_action in ('device_only', 'device_and_user') else '',
            mode=rec_action,
            reason=f"حظر بقرار التحليل الأمني الذكي: {verdict['reason_ar'][:180]}",
            block_type='permanent',
            actor=None,
            request=request,
        )

    return {
        'profile': profile,
        'verdict': verdict,
        'enforcement': enforcement_res,
    }


def _pick_riskiest_installation_id(telemetry: dict[str, Any]) -> str:
    for d in telemetry.get('devices') or []:
        if d.get('mitm_ca_detected') or d.get('proxy_detected') or d.get('frida_detected') or d.get('hooking_detected'):
            return str(d.get('installation_id') or '')
    devices = telemetry.get('devices') or []
    return str(devices[0].get('installation_id') or '') if devices else ''


def _derive_heuristic_action(score: int, reasons: list[str], telemetry: dict[str, Any]) -> str:
    if telemetry.get('proxy_tamper_strikes', 0) > 0:
        return 'device_and_user' if score >= 85 else 'device_only'
    if any('sharing' in r or 'multiple_ips' in r for r in reasons) and score >= 85:
        return 'user_only'
    if score >= 85:
        return 'device_and_user'
    if score >= 50:
        return 'warn'
    return 'none'


def run_hourly_ai_behavioral_audit(*, force: bool = False, request=None) -> dict[str, Any]:
    """
    مهمة التدقيق الدورية كل ساعة: تحلل سلوك كل المستخدمين الذين دخلوا أو تفاعلوا على المنصة اليوم
    وتتخذ إجراء الحظر المناسب (جهاز فقط / حساب فقط / كلاهما) تلقائياً حسب السياسة.
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()
    policy = SecurityPolicyConfig.load()
    ai_cfg = get_effective_ai_config(policy)
    now = timezone.now()
    if not force and not policy.ai_hourly_schedule_enabled:
        return {'skipped': True, 'reason': 'hourly_schedule_disabled'}

    today_start = timezone.localtime(now).replace(hour=0, minute=0, second=0, microsecond=0)
    user_ids = set(
        DeviceActivity.objects.filter(created_at__gte=today_start, user_id__isnull=False)
        .values_list('user_id', flat=True)
        .distinct()
    )
    user_ids.update(
        DeviceSession.objects.filter(last_seen_at__gte=today_start)
        .values_list('user_id', flat=True)
        .distinct()
    )
    user_ids.update(
        User.objects.filter(last_login__gte=today_start)
        .values_list('id', flat=True)
        .distinct()
    )

    from api_v1.models import RegisteredDevice

    users_qs = User.objects.filter(id__in=user_ids, is_active=True, is_superuser=False).exclude(role='admin')
    if force and not users_qs.exists():
        fallback_ids = set(
            RegisteredDevice.objects.values_list('user_id', flat=True).distinct()[:25]
        )
        fallback_ids.update(
            UserSecurityProfile.objects.values_list('user_id', flat=True)[:25]
        )
        users_qs = (
            User.objects.filter(id__in=fallback_ids, is_active=True, is_superuser=False)
            .exclude(role='admin')
            .order_by('-last_login', '-id')
        )
        if not users_qs.exists():
            users_qs = (
                User.objects.filter(is_active=True, is_superuser=False)
                .exclude(role='admin')
                .order_by('-last_login', '-id')
            )
        users = users_qs[:25]
    else:
        users = users_qs
    analyzed_users = 0
    flagged_high_risk = 0
    banned_users = 0
    banned_devices = 0
    used_external_ai = False

    for u in users:
        res = analyze_user_with_ai(u, enforce_if_flagged=True, request=request)
        analyzed_users += 1
        if res['verdict'].get('used_external_ai'):
            used_external_ai = True
        if res['verdict'].get('risk_score', 0) >= policy.risk_threshold_high:
            flagged_high_risk += 1
        enf = res.get('enforcement')
        if isinstance(enf, dict) and enf.get('enforced'):
            if enf.get('user_banned'):
                banned_users += 1
            banned_devices += int(enf.get('blocked_devices') or 0)

    summary = {
        'analyzed_users': analyzed_users,
        'flagged_high_risk': flagged_high_risk,
        'banned_users': banned_users,
        'banned_devices': banned_devices,
        'used_external_ai': used_external_ai,
        'ai_key_configured': ai_cfg['configured'],
        'provider': ai_cfg['provider'],
        'model': ai_cfg['model'],
        'ran_at': now.isoformat(),
    }
    existing_summary = policy.last_ai_audit_summary if isinstance(policy.last_ai_audit_summary, dict) else {}
    existing_flags = existing_summary.get('boot_guard_flags')
    if isinstance(existing_flags, dict):
        summary['boot_guard_flags'] = existing_flags
    policy.last_ai_audit_at = now
    policy.last_ai_audit_summary = summary
    policy.save(update_fields=['last_ai_audit_at', 'last_ai_audit_summary', 'updated_at'])
    return summary


def maybe_trigger_hourly_ai_audit_async() -> None:
    """تشغيل التدقيق السلوكي الساعي في الخلفية بأمان بمجرد مرور ساعة على آخر فحص."""
    import sys
    import threading

    if 'test' in sys.argv:
        return
    if not cache.add('ta3alm:ai_hourly_audit_probe', 1, timeout=180):
        return
    try:
        policy = SecurityPolicyConfig.load()
        if not policy.ai_security_enabled or not policy.ai_hourly_schedule_enabled:
            return
        now = timezone.now()
        if policy.last_ai_audit_at and (now - policy.last_ai_audit_at) < timedelta(hours=1):
            return
        if not cache.add('ta3alm:ai_hourly_audit_running', 1, timeout=3500):
            return

        def _worker():
            from django.db import close_old_connections
            try:
                close_old_connections()
                run_hourly_ai_behavioral_audit(force=False, request=None)
            except Exception:
                pass
            finally:
                close_old_connections()
                cache.delete('ta3alm:ai_hourly_audit_running')

        threading.Thread(target=_worker, daemon=True).start()
    except Exception:
        pass
