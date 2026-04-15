/**
 * VPN Subscription Parser Bot
 * Парсит vless/ss конфиги из зашифрованных (base64) подписок
 *
 * Зависимости:  npm install telegraf axios
 * Запуск:       BOT_TOKEN=xxx node vpn-sub-parser-bot.js
 */

'use strict';

const { Telegraf } = require('telegraf');
const axios        = require('axios');

// ─── Конфиг ─────────────────────────────────────────────────────────────────
const BOT_TOKEN   = process.env.BOT_TOKEN || 'YOUR_BOT_TOKEN_HERE';
const MAX_CONFIGS = 50;   // сколько конфигов показывать в списке
const PAGE_SIZE   = 10;   // конфигов на одну страницу

// ─── Хранилище (in-memory) ───────────────────────────────────────────────────
/** userId → { configs, url, ts } */
const store = new Map();

// ─── Парсеры ─────────────────────────────────────────────────────────────────

function parseVless(raw) {
  try {
    const body      = raw.slice('vless://'.length);
    const hashIdx   = body.lastIndexOf('#');
    const name      = hashIdx !== -1 ? tryDecode(body.slice(hashIdx + 1).trim()) : 'Unknown';
    const main      = hashIdx !== -1 ? body.slice(0, hashIdx) : body;
    const atIdx     = main.indexOf('@');
    const uuid      = main.slice(0, atIdx);
    const rest      = main.slice(atIdx + 1);
    const qIdx      = rest.indexOf('?');
    const hostPort  = qIdx !== -1 ? rest.slice(0, qIdx) : rest;
    const queryStr  = qIdx !== -1 ? rest.slice(qIdx + 1) : '';
    const lastColon = hostPort.lastIndexOf(':');
    const host      = hostPort.slice(0, lastColon);
    const port      = hostPort.slice(lastColon + 1);
    const params    = parseQuery(queryStr);

    return {
      proto:    'vless',
      uuid, host, port,
      security: params.security || 'none',
      type:     params.type     || 'tcp',
      flow:     params.flow     || '',
      sni:      params.sni      || '',
      fp:       params.fp       || '',
      name, raw,
    };
  } catch { return null; }
}

function parseSs(raw) {
  try {
    const body    = raw.slice('ss://'.length);
    const hashIdx = body.lastIndexOf('#');
    const name    = hashIdx !== -1 ? tryDecode(body.slice(hashIdx + 1).trim()) : 'Unknown';
    const main    = hashIdx !== -1 ? body.slice(0, hashIdx) : body;

    let method = '', password = '', host = '', port = '';

    if (main.includes('@')) {
      // SIP002: ss://base64-or-plain@host:port
      const atIdx   = main.lastIndexOf('@');
      const creds   = main.slice(0, atIdx);
      const hostPort = main.slice(atIdx + 1);

      let decoded = creds;
      try { decoded = Buffer.from(creds, 'base64').toString(); } catch {}
      [method, ...rest] = decoded.split(':');
      password = rest.join(':');

      const lc = hostPort.lastIndexOf(':');
      host = hostPort.slice(0, lc);
      port = hostPort.slice(lc + 1);
    } else {
      // Legacy: ss://base64(method:pass@host:port)
      const decoded = Buffer.from(main, 'base64').toString();
      const atIdx   = decoded.lastIndexOf('@');
      const creds   = decoded.slice(0, atIdx);
      const hostPort = decoded.slice(atIdx + 1);
      [method, ...rest] = creds.split(':');
      password = rest.join(':');
      const lc = hostPort.lastIndexOf(':');
      host = hostPort.slice(0, lc);
      port = hostPort.slice(lc + 1);
    }

    return { proto: 'ss', method, password, host, port, name, raw };
  } catch { return null; }
}

function parseOther(raw) {
  const proto = raw.split('://')[0];
  const hashIdx = raw.lastIndexOf('#');
  const name = hashIdx !== -1 ? tryDecode(raw.slice(hashIdx + 1).trim()) : 'Unknown';
  return { proto, name, raw };
}

// ─── Утилиты ─────────────────────────────────────────────────────────────────

function tryDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function parseQuery(qs) {
  const out = {};
  if (!qs) return out;
  qs.split('&').forEach(p => {
    const i = p.indexOf('=');
    if (i === -1) return;
    const k = p.slice(0, i);
    const v = p.slice(i + 1);
    out[k] = tryDecode(v);
  });
  return out;
}

/**
 * Загружает подписку и возвращает массив распарсенных конфигов
 */
async function fetchAndParse(url) {
  const resp = await axios.get(url, {
    timeout: 20_000,
    headers: { 'User-Agent': 'clash-verge/1.6.6' },
    maxContentLength: 15 * 1024 * 1024,
    responseType: 'text',
  });

  let text = String(resp.data).trim();

  // Пробуем декодировать base64
  const isB64 = /^[A-Za-z0-9+/\r\n]+=*$/.test(text.replace(/\s/g, ''));
  if (isB64 && !text.startsWith('vless://') && !text.startsWith('ss://')) {
    try { text = Buffer.from(text.replace(/\s/g, ''), 'base64').toString('utf-8'); }
    catch {}
  }

  const known = ['vless://', 'ss://', 'vmess://', 'trojan://', 'hysteria://', 'hysteria2://', 'tuic://', 'hy2://'];
  const lines = text.split('\n').map(l => l.trim()).filter(l => known.some(p => l.startsWith(p)));

  const configs = [];
  for (const line of lines) {
    if      (line.startsWith('vless://')) { const c = parseVless(line); if (c) configs.push(c); }
    else if (line.startsWith('ss://'))    { const c = parseSs(line);    if (c) configs.push(c); }
    else                                  { configs.push(parseOther(line)); }
  }
  return configs;
}

// ─── Форматирование сообщений ─────────────────────────────────────────────────

function statsMessage(configs, url) {
  const byProto = {};
  const hosts   = {};
  const secTypes = {};

  for (const c of configs) {
    byProto[c.proto] = (byProto[c.proto] || 0) + 1;
    if (c.host) hosts[c.host] = (hosts[c.host] || 0) + 1;
    if (c.security) secTypes[c.security] = (secTypes[c.security] || 0) + 1;
  }

  const total       = configs.length;
  const uniqueHosts = Object.keys(hosts).length;

  let msg = `<tg-emoji emoji-id="5870633910337015697">✅</tg-emoji> <b>Подписка загружена!</b>\n\n`;
  msg    += `<tg-emoji emoji-id="5870921681735781843">📊</tg-emoji> <b>Статистика:</b>\n`;
  msg    += `┌ Всего конфигов: <b>${total}</b>\n`;

  const protoKeys = Object.keys(byProto);
  protoKeys.forEach((p, i) => {
    const last   = i === protoKeys.length - 1 && uniqueHosts === 0;
    const prefix = last ? '└' : '├';
    msg += `${prefix} <code>${p}://</code> — <b>${byProto[p]}</b>\n`;
  });

  if (uniqueHosts > 0) {
    msg += `└ Уникальных серверов: <b>${uniqueHosts}</b>\n`;
  }

  if (Object.keys(secTypes).length > 0) {
    msg += `\n<tg-emoji emoji-id="6037249452824072506">🔒</tg-emoji> <b>Безопасность:</b>\n`;
    const secKeys = Object.keys(secTypes);
    secKeys.forEach((s, i) => {
      msg += `${i === secKeys.length - 1 ? '└' : '├'} ${s}: <b>${secTypes[s]}</b>\n`;
    });
  }

  if (uniqueHosts > 0 && uniqueHosts <= 12) {
    msg += `\n<tg-emoji emoji-id="5873147866364514353">🏘</tg-emoji> <b>Серверы:</b>\n`;
    const entries = Object.entries(hosts);
    entries.forEach(([h, cnt], i) => {
      msg += `${i === entries.length - 1 ? '└' : '├'} <code>${h}</code> — ${cnt} конф.\n`;
    });
  }

  return msg;
}

function configsListMessage(configs, page) {
  const start = page * PAGE_SIZE;
  const slice = configs.slice(start, start + PAGE_SIZE);
  const total = configs.length;

  let msg = `<tg-emoji emoji-id="5870676941614354370">🖋</tg-emoji> <b>Конфиги (${start + 1}–${start + slice.length} из ${total}):</b>\n\n`;

  slice.forEach((c, idx) => {
    const n = start + idx + 1;
    const cleanName = (c.name || 'Unknown').replace(/<[^>]*>/g, '').slice(0, 60);
    msg += `<b>${n}.</b> <code>${c.host || '?'}:${c.port || '?'}</code>`;
    if (c.security && c.security !== 'none') msg += ` <tg-emoji emoji-id="6037249452824072506">🔒</tg-emoji><i>${c.security}</i>`;
    msg += `\n   <tg-emoji emoji-id="5886285355279193209">🏷</tg-emoji> ${cleanName}\n`;
    if (c.sni) msg += `   <tg-emoji emoji-id="5870801517140775623">🔗</tg-emoji> SNI: <code>${c.sni}</code>\n`;
    msg += '\n';
  });

  return msg;
}

function paginationKeyboard(page, totalConfigs) {
  const maxPage = Math.ceil(totalConfigs / PAGE_SIZE) - 1;
  const row = [];
  if (page > 0)       row.push({ text: '◁ Назад', callback_data: `page:${page - 1}`, icon_custom_emoji_id: '5893057118545646106' });
  if (page < maxPage) row.push({ text: 'Вперёд ▷', callback_data: `page:${page + 1}`, icon_custom_emoji_id: '5893057118545646106' });
  const buttons = [
    [
      { text: 'Скачать .txt', callback_data: 'download', icon_custom_emoji_id: '6039802767931871481' },
      { text: 'Статистика',   callback_data: 'stats',    icon_custom_emoji_id: '5870921681735781843' },
    ]
  ];
  if (row.length) buttons.unshift(row);
  return { inline_keyboard: buttons };
}

function mainKeyboard(totalConfigs) {
  return {
    inline_keyboard: [
      [
        { text: 'Список конфигов', callback_data: 'page:0', icon_custom_emoji_id: '5870676941614354370' },
        { text: 'Скачать .txt',    callback_data: 'download', icon_custom_emoji_id: '6039802767931871481' },
      ],
    ]
  };
}

// ─── Бот ─────────────────────────────────────────────────────────────────────

const bot = new Telegraf(BOT_TOKEN);

// /start
bot.start(async (ctx) => {
  const name = ctx.from.first_name || 'пользователь';
  await ctx.reply(
    `<tg-emoji emoji-id="6030400221232501136">🤖</tg-emoji> <b>Привет, ${name}!</b>\n\n` +
    `Я умею парсить VPN-подписки и извлекать конфиги.\n\n` +
    `<tg-emoji emoji-id="6028435952299413210">ℹ️</tg-emoji> <b>Как пользоваться:</b>\n` +
    `Просто отправь ссылку на подписку — я декодирую base64, найду все конфиги и покажу статистику.\n\n` +
    `<tg-emoji emoji-id="5870633910337015697">✅</tg-emoji> <b>Поддерживаемые протоколы:</b>\n` +
    `<code>vless://</code>  <code>ss://</code>  <code>vmess://</code>  <code>trojan://</code>  <code>hysteria://</code>`,
    {
      parse_mode: 'HTML',
      reply_markup: {
        keyboard: [
          [{ text: 'ℹ️ Помощь', icon_custom_emoji_id: '6028435952299413210' }]
        ],
        resize_keyboard: true,
      }
    }
  );
});

// /help
bot.help(async (ctx) => {
  await ctx.reply(
    `<tg-emoji emoji-id="6028435952299413210">ℹ️</tg-emoji> <b>Помощь</b>\n\n` +
    `<b>Что умеет бот:</b>\n` +
    `• Загружает подписки по HTTP/HTTPS\n` +
    `• Декодирует base64-контент\n` +
    `• Парсит vless, ss, vmess, trojan, hysteria\n` +
    `• Показывает статистику по протоколам и серверам\n` +
    `• Выдаёт список конфигов постранично\n` +
    `• Отдаёт все конфиги в виде .txt файла\n\n` +
    `<b>Формат ссылки:</b>\n` +
    `<code>https://example.com/sub/YOUR-TOKEN</code>`,
    { parse_mode: 'HTML' }
  );
});

// Текстовые сообщения — ссылки на подписки
bot.on('text', async (ctx) => {
  const text = ctx.message.text.trim();

  if (!text.startsWith('http://') && !text.startsWith('https://')) {
    await ctx.reply(
      `<tg-emoji emoji-id="5870657884844462243">❌</tg-emoji> Это не похоже на ссылку.\n` +
      `Отправь URL подписки, например:\n` +
      `<code>https://vpn.example.com/sub/your-token</code>`,
      { parse_mode: 'HTML' }
    );
    return;
  }

  const statusMsg = await ctx.reply(
    `<tg-emoji emoji-id="5345906554510012647">🔄</tg-emoji> <b>Загружаю подписку...</b>`,
    { parse_mode: 'HTML' }
  );

  try {
    const configs = await fetchAndParse(text);

    if (configs.length === 0) {
      await ctx.telegram.editMessageText(
        ctx.chat.id, statusMsg.message_id, undefined,
        `<tg-emoji emoji-id="5870657884844462243">❌</tg-emoji> <b>Конфиги не найдены.</b>\n\n` +
        `Проверь ссылку или убедись, что подписка содержит поддерживаемые протоколы.`,
        { parse_mode: 'HTML' }
      );
      return;
    }

    store.set(ctx.from.id, { configs, url: text, ts: Date.now() });

    await ctx.telegram.editMessageText(
      ctx.chat.id, statusMsg.message_id, undefined,
      statsMessage(configs, text),
      { parse_mode: 'HTML', reply_markup: mainKeyboard(configs.length) }
    );

  } catch (err) {
    const hint = friendlyError(err);
    await ctx.telegram.editMessageText(
      ctx.chat.id, statusMsg.message_id, undefined,
      `<tg-emoji emoji-id="5870657884844462243">❌</tg-emoji> <b>Ошибка при загрузке:</b>\n<code>${hint}</code>`,
      { parse_mode: 'HTML' }
    );
  }
});

// Пагинация
bot.action(/^page:(\d+)$/, async (ctx) => {
  const page = parseInt(ctx.match[1]);
  const data = store.get(ctx.from.id);
  if (!data) { await ctx.answerCbQuery('⏰ Данные устарели — отправь ссылку снова'); return; }

  const { configs } = data;
  const msg = configsListMessage(configs, page);

  try {
    await ctx.editMessageText(msg, {
      parse_mode: 'HTML',
      reply_markup: paginationKeyboard(page, configs.length),
    });
  } catch {}
  await ctx.answerCbQuery();
});

// Статистика
bot.action('stats', async (ctx) => {
  const data = store.get(ctx.from.id);
  if (!data) { await ctx.answerCbQuery('⏰ Данные устарели — отправь ссылку снова'); return; }

  try {
    await ctx.editMessageText(statsMessage(data.configs, data.url), {
      parse_mode: 'HTML',
      reply_markup: mainKeyboard(data.configs.length),
    });
  } catch {}
  await ctx.answerCbQuery();
});

// Скачать .txt
bot.action('download', async (ctx) => {
  const data = store.get(ctx.from.id);
  if (!data) { await ctx.answerCbQuery('⏰ Данные устарели — отправь ссылку снова'); return; }

  await ctx.answerCbQuery('📥 Готовлю файл...');

  const content = data.configs.map(c => c.raw).join('\n');
  const buf     = Buffer.from(content, 'utf-8');

  await ctx.replyWithDocument(
    { source: buf, filename: 'configs.txt' },
    {
      caption:
        `<tg-emoji emoji-id="5870633910337015697">✅</tg-emoji> ` +
        `<b>${data.configs.length} конфигов</b> из подписки`,
      parse_mode: 'HTML',
    }
  );
});

// ─── Хелпер ошибок ───────────────────────────────────────────────────────────

function friendlyError(err) {
  if (err.code === 'ENOTFOUND')     return 'Домен не найден (ENOTFOUND)';
  if (err.code === 'ECONNREFUSED')  return 'Сервер отклонил соединение';
  if (err.code === 'ETIMEDOUT')     return 'Таймаут соединения';
  if (err.response?.status === 403) return 'Доступ запрещён (HTTP 403)';
  if (err.response?.status === 404) return 'Страница не найдена (HTTP 404)';
  if (err.response?.status === 429) return 'Слишком много запросов (HTTP 429)';
  return err.message || String(err);
}

// ─── Запуск ───────────────────────────────────────────────────────────────────

bot.launch()
  .then(() => console.log('✅ Bot started'))
  .catch(err => { console.error('❌ Failed to start:', err); process.exit(1); });

process.once('SIGINT',  () => bot.stop('SIGINT'));
process.once('SIGTERM', () => bot.stop('SIGTERM'));
