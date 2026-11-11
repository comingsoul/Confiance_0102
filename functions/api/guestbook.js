// 방명록 API (Cloudflare Pages Functions)
// Pages 프로젝트 > 설정 > 바인딩(Functions) 에서 KV 네임스페이스를 변수 이름 GUESTBOOK 으로 연결해야 합니다.
// 글은 KV 키 "entries" 하나에 최신순 배열(JSON)로 저장됩니다.
// 삭제: 글쓴이가 정한 비밀번호, 또는 관리자 비밀번호(환경 변수 ADMIN_PASSWORD, 선택)로 지울 수 있습니다.

const MAX_ENTRIES = 1000;
const NAME_MAX = 20;
const MESSAGE_MAX = 300;
const PASSWORD_MIN = 4;
const PASSWORD_MAX = 20;
const COOLDOWN_SEC = 60; // 같은 IP 연속 등록 제한 (KV 최소 만료 시간이 60초)

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });

const clean = (s, max) =>
  String(s || '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .replace(/\r\n?/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
    .slice(0, max);

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function hashPassword(password, salt) {
  return toHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + ':' + password)));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// 화면에 내보낼 때는 비밀번호 해시를 빼고 보냄
const publicEntry = ({ id, name, message, ts }) => ({ id, name, message, ts });

async function readEntries(env) {
  return (await env.GUESTBOOK.get('entries', 'json')) || [];
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export async function onRequestGet({ env }) {
  if (!env.GUESTBOOK) return json({ error: '방명록이 아직 준비되지 않았습니다' }, 503);
  return json({ entries: (await readEntries(env)).map(publicEntry) });
}

export async function onRequestPost({ request, env }) {
  if (!env.GUESTBOOK) return json({ error: '방명록이 아직 준비되지 않았습니다' }, 503);

  const body = await readBody(request);
  if (!body) return json({ error: '잘못된 요청입니다' }, 400);
  // 봇이 채우는 숨은 칸
  if (body.website) return json({ error: '잘못된 요청입니다' }, 400);

  const name = clean(body.name, NAME_MAX).replace(/\n/g, ' ');
  const message = clean(body.message, MESSAGE_MAX);
  const password = String(body.password || '');
  if (!name || !message) return json({ error: '이름과 메시지를 입력해 주세요' }, 400);
  if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
    return json({ error: `비밀번호는 ${PASSWORD_MIN}~${PASSWORD_MAX}자로 입력해 주세요` }, 400);
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const rlKey = 'rl:' + ip;
  if (await env.GUESTBOOK.get(rlKey)) {
    return json({ error: '잠시 후 다시 남겨주세요' }, 429);
  }
  await env.GUESTBOOK.put(rlKey, '1', { expirationTtl: COOLDOWN_SEC });

  const salt = crypto.randomUUID();
  const entry = { id: crypto.randomUUID(), name, message, ts: Date.now(), salt, hash: await hashPassword(password, salt) };
  const entries = await readEntries(env);
  entries.unshift(entry);
  await env.GUESTBOOK.put('entries', JSON.stringify(entries.slice(0, MAX_ENTRIES)));

  return json({ entry: publicEntry(entry) }, 201);
}

export async function onRequestDelete({ request, env }) {
  if (!env.GUESTBOOK) return json({ error: '방명록이 아직 준비되지 않았습니다' }, 503);

  const body = await readBody(request);
  if (!body || !body.id) return json({ error: '잘못된 요청입니다' }, 400);
  const password = String(body.password || '');
  if (!password) return json({ error: '비밀번호를 입력해 주세요' }, 400);

  // 비밀번호 대입 시도 제한: IP당 1분에 5번
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const tryKey = 'del:' + ip;
  const tries = Number(await env.GUESTBOOK.get(tryKey)) || 0;
  if (tries >= 5) return json({ error: '잠시 후 다시 시도해 주세요' }, 429);

  const entries = await readEntries(env);
  const idx = entries.findIndex((e) => e.id === body.id);
  if (idx < 0) return json({ error: '이미 삭제된 글입니다' }, 404);

  const e = entries[idx];
  const isOwner = e.hash && safeEqual(await hashPassword(password, e.salt), e.hash);
  const isAdmin = env.ADMIN_PASSWORD && safeEqual(password, String(env.ADMIN_PASSWORD));
  if (!isOwner && !isAdmin) {
    await env.GUESTBOOK.put(tryKey, String(tries + 1), { expirationTtl: 60 });
    return json({ error: '비밀번호가 맞지 않습니다' }, 403);
  }

  entries.splice(idx, 1);
  await env.GUESTBOOK.put('entries', JSON.stringify(entries));
  return json({ ok: true });
}
