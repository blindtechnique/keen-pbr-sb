// keen-pbr-sb — сайт проекта
(() => {
  'use strict';

  /* ── тема ─────────────────────────────────────── */
  const html = document.documentElement;
  const saved = localStorage.getItem('kpbr-theme');
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  html.dataset.theme = saved || (prefersDark ? 'dark' : 'light');

  document.getElementById('theme').addEventListener('click', () => {
    html.dataset.theme = html.dataset.theme === 'dark' ? 'light' : 'dark';
    localStorage.setItem('kpbr-theme', html.dataset.theme);
  });

  /* ── мобильное меню ───────────────────────────── */
  const burger = document.getElementById('burger');
  const nav = document.getElementById('nav');
  burger.addEventListener('click', () => {
    const open = nav.classList.toggle('open');
    burger.setAttribute('aria-expanded', String(open));
  });
  nav.addEventListener('click', (e) => {
    if (e.target.tagName === 'A') {
      nav.classList.remove('open');
      burger.setAttribute('aria-expanded', 'false');
    }
  });

  /* ── вкладки галереи ──────────────────────────── */
  const tabs = [...document.querySelectorAll('.tab')];
  const show = (id) => {
    tabs.forEach((t) => {
      const on = t.dataset.p === id;
      t.setAttribute('aria-selected', String(on));
      document.getElementById(t.dataset.p).hidden = !on;
    });
  };
  tabs.forEach((t) => t.addEventListener('click', () => show(t.dataset.p)));
  tabs.forEach((t, i) =>
    t.addEventListener('keydown', (e) => {
      const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      e.preventDefault();
      const next = tabs[(i + d + tabs.length) % tabs.length];
      next.focus();
      show(next.dataset.p);
    })
  );

  /* ── лайтбокс ─────────────────────────────────── */
  const lb = document.getElementById('lb');
  const lbimg = document.getElementById('lbimg');
  document.querySelectorAll('.shot img, .hero__shot img').forEach((img) => {
    img.parentElement.addEventListener('click', () => {
      lbimg.src = img.src;
      lbimg.alt = img.alt;
      lb.hidden = false;
      document.body.style.overflow = 'hidden';
    });
  });
  const closeLb = () => {
    lb.hidden = true;
    lbimg.src = '';
    document.body.style.overflow = '';
  };
  lb.addEventListener('click', closeLb);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !lb.hidden) closeLb();
  });

  /* ── копирование команды ──────────────────────── */
  const copy = document.getElementById('copy');
  copy.addEventListener('click', async () => {
    const text = copy.dataset.cmd;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    const was = copy.textContent;
    copy.textContent = 'Скопировано';
    setTimeout(() => (copy.textContent = was), 1800);
  });

  /* ── версия из GitHub, если доступна ──────────── */
  fetch('https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/latest')
    .then((r) => (r.ok ? r.json() : null))
    .then((d) => {
      if (!d || !d.tag_name) return;
      const el = document.getElementById('latest-release');
      if (el) {
        el.textContent = 'Последний стабильный ' + d.tag_name;
        el.href = 'https://github.com/blindtechnique/keen-pbr-sb/releases/tag/' + encodeURIComponent(d.tag_name);
      }
    })
    .catch(() => {});

  // Promotion removes Beta without changing the illustrated release identity.
  const currentRelease = document.getElementById('current-release');
  if (currentRelease) {
    const tag = currentRelease.dataset.tag;
    fetch('https://api.github.com/repos/blindtechnique/keen-pbr-sb/releases/tags/' + encodeURIComponent(tag))
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => {
        if (!d || d.tag_name !== tag || d.draft) return;
        currentRelease.textContent = tag + (d.prerelease ? ' · Beta' : '');
        currentRelease.href = 'https://github.com/blindtechnique/keen-pbr-sb/releases/tag/' + encodeURIComponent(tag);
      })
      .catch(() => {});
  }
})();
