async function hmacCode(secret, input) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(input));
  const bytes = Array.from(new Uint8Array(sig));
  const hex = bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  const short = hex.slice(0, 8).toUpperCase();
  return short.slice(0, 4) + "-" + short.slice(4, 8);
}
function corsHeaders() {
  return { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" };
}
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...corsHeaders() } });
}
function adminPage() {
  return `<!DOCTYPE html><html dir="rtl" lang="fa"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>پنل مدیریت زمین‌کاو</title><style>body{font-family:Tahoma,sans-serif;max-width:480px;margin:40px auto;padding:0 16px;background:#f5f5f7}h2{text-align:center}.box{background:#fff;border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 1px 4px rgba(0,0,0,.1)}label{display:block;margin-bottom:6px;font-weight:bold}input,select{width:100%;padding:10px;margin-bottom:14px;border:1px solid #ccc;border-radius:8px;box-sizing:border-box;font-size:16px}button{width:100%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer}#result{margin-top:14px;padding:12px;background:#eef;border-radius:8px;text-align:center;font-size:20px;font-weight:bold;letter-spacing:1px;direction:ltr;display:none}.err{color:#c00;text-align:center}</style></head><body><h2>پنل تولید کد - زمین‌کاو</h2><div class="box"><label>رمز عبور مدیر</label><input type="password" id="pwd" placeholder="رمز عبور"><label>نوع کد</label><select id="type"><option value="activation">کد فعال‌سازی (Device ID)</option><option value="unlock">کد آزادسازی (Seed)</option></select><label>مقدار (Device ID یا Seed)</label><input type="text" id="input" placeholder="مثلاً ABC12345"><button onclick="generate()">تولید کد</button><div id="result"></div><div id="error" class="err"></div></div><script>async function generate(){const pwd=document.getElementById('pwd').value;const type=document.getElementById('type').value;const input=document.getElementById('input').value.trim();const resultEl=document.getElementById('result');const errEl=document.getElementById('error');resultEl.style.display='none';errEl.textContent='';if(!pwd||!input){errEl.textContent='لطفاً رمز عبور و مقدار را وارد کنید';return;}try{const res=await fetch('/admin/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pwd,type,input})});const data=await res.json();if(!res.ok){errEl.textContent=data.error||'خطا در تولید کد';return;}resultEl.textContent=data.code;resultEl.style.display='block';}catch(e){errEl.textContent='خطا در ارتباط با سرور';}}</script></body></html>`;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders() });
    if (url.pathname === "/" && request.method === "GET") return new Response("Void Scanner license server is running.", { headers: corsHeaders() });
    if (url.pathname === "/admin" && request.method === "GET") return new Response(adminPage(), { headers: { "Content-Type": "text/html; charset=utf-8" } });
    if (url.pathname === "/admin/generate" && request.method === "POST") {
      try {
        const body = await request.json();
        const { password, type, input } = body;
        if (password !== env.ADMIN_PASSWORD) return jsonResponse({ error: "رمز عبور اشتباه است" }, 401);
        if (!input || (type !== "activation" && type !== "unlock")) return jsonResponse({ error: "ورودی نامعتبر" }, 400);
        const secret = type === "activation" ? env.ACTIVATION_SECRET : env.LOCK_SECRET;
        const code = await hmacCode(secret, input);
        return jsonResponse({ code });
      } catch (e) {
        return jsonResponse({ error: "خطای سرور" }, 500);
      }
    }
    if (url.pathname === "/verify" && request.method === "POST") {
      try {
        const body = await request.json();
        const { type, input, code } = body;
        if (!input || !code || (type !== "activation" && type !== "unlock")) return jsonResponse({ valid: false, error: "ورودی نامعتبر" }, 400);
        const secret = type === "activation" ? env.ACTIVATION_SECRET : env.LOCK_SECRET;
        const expected = await hmacCode(secret, input);
        const valid = expected === String(code).toUpperCase().trim();
        return jsonResponse({ valid });
      } catch (e) {
        return jsonResponse({ valid: false, error: "خطای سرور" }, 500);
      }
    }
    return jsonResponse({ error: "Not found" }, 404);
  },
};
