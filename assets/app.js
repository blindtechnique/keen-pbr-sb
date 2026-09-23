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
  lb?.addEventListener('click', closeLb);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && lb && !lb.hidden) closeLb();
  });

  /* ── копирование команды ──────────────────────── */
  document.querySelectorAll('[data-copy-target], [data-cmd]').forEach((copy) => {
    copy.setAttribute('aria-live', 'polite');
    copy.addEventListener('click', async () => {
      const source = document.getElementById(copy.dataset.copyTarget);
      const text = source?.textContent ?? copy.dataset.cmd;
      if (!text || copy.disabled) return;
      const was = copy.textContent;
      copy.disabled = true;
      let copied = false;
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try {
          copied = document.execCommand('copy');
        } catch {
          copied = false;
        } finally {
          ta.remove();
        }
      }
      copy.textContent = copied ? 'Скопировано' : 'Выделите команду вручную';
      setTimeout(() => {
        copy.textContent = was;
        copy.disabled = false;
      }, 1800);
    });
  });

})();
