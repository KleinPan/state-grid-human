"""HTTP view for the human captcha page."""
from __future__ import annotations

import html
import json

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from .captcha import STORE, normalize_clicks
from .const import CAPTCHA_VIEW


class CaptchaView(HomeAssistantView):
    """Render a captcha and submit clicks back to the config flow."""

    requires_auth = True
    url = f"{CAPTCHA_VIEW}/{{flow_id}}"
    name = "api:state_grid_human:captcha"

    async def get(self, request: web.Request, flow_id: str) -> web.Response:
        session = STORE.get(flow_id)
        if session is None:
            return web.Response(status=404, text="Captcha session expired")

        canvas = session.canvas
        if canvas and not canvas.startswith("data:"):
            canvas = f"data:image/png;base64,{canvas}"
        target = html.escape(session.target_text or "请依次点击指定图标")
        max_clicks = len(session.icons) or 3
        safe_canvas = html.escape(canvas, quote=True)

        page = f"""<!doctype html>
<html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>国家电网安全验证</title>
<style>
body{{font-family:system-ui,sans-serif;background:#f5f5f5;margin:0;padding:24px;color:#222}}
main{{max-width:520px;margin:auto;background:#fff;border-radius:16px;padding:20px;box-shadow:0 4px 24px #0001}}
h2{{margin:0 0 8px}} .hint{{margin:0 0 16px;font-size:18px}}
#wrap{{position:relative;width:min(100%,310px);margin:auto}}
#captcha{{display:block;width:100%;height:auto;touch-action:none;user-select:none}}
.dot{{position:absolute;width:22px;height:22px;border:3px solid #1677ff;border-radius:50%;transform:translate(-50%,-50%);box-sizing:border-box}}
button{{width:100%;margin-top:16px;height:44px;border:0;border-radius:10px;background:#1677ff;color:#fff;font-size:16px}}
button:disabled{{opacity:.5}} #status{{margin-top:12px;text-align:center}}
</style><main>
<h2>国家电网安全验证</h2><p class="hint">{target}</p>
<div id="wrap"><img id="captcha" src="{safe_canvas}" alt="验证码"></div>
<button id="ok" disabled>确定</button><div id="status"></div>
<script>
const wrap=document.getElementById('wrap'),img=document.getElementById('captcha'),ok=document.getElementById('ok'),status=document.getElementById('status');
const clicks=[];const maxClicks={max_clicks};
img.addEventListener('click',e=>{{if(clicks.length>=maxClicks)return;const r=img.getBoundingClientRect();const x=Math.round((e.clientX-r.left)*img.naturalWidth/r.width);const y=Math.round((e.clientY-r.top)*img.naturalHeight/r.height);clicks.push({{x,y}});const d=document.createElement('i');d.className='dot';d.style.left=(e.clientX-r.left)+'px';d.style.top=(e.clientY-r.top)+'px';wrap.appendChild(d);ok.disabled=clicks.length!==maxClicks;}});
ok.onclick=async()=>{{ok.disabled=true;status.textContent='正在提交…';try{{const r=await fetch('/api/config/config_entries/flow/{flow_id}',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{clicks}})}});const data=await r.json();if(data.type==='abort'){{status.textContent=data.description||data.reason||'验证失败';return;}}window.close();}}catch(e){{status.textContent='提交失败：'+e;ok.disabled=false;}}}};
</script></main></html>"""
        return web.Response(text=page, content_type="text/html")

    async def post(self, request: web.Request, flow_id: str) -> web.Response:
        session = STORE.get(flow_id)
        if session is None:
            return web.json_response({"error": "captcha_expired"}, status=404)
        try:
            payload = await request.json()
            normalize_clicks(payload.get("clicks"))
        except (ValueError, TypeError, json.JSONDecodeError) as err:
            return web.json_response({"error": str(err)}, status=400)
        return web.json_response({"ok": True})
