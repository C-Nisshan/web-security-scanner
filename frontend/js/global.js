/* global.js — shared behaviour: navbar scroll, mobile menu */

document.addEventListener('DOMContentLoaded', () => {
  // Scroll effect on navbar
  const nav = document.querySelector('.aegis-navbar');
  if (nav) {
    window.addEventListener('scroll', () => {
      nav.classList.toggle('scrolled', window.scrollY > 40);
    }, { passive: true });
  }

  // Highlight active nav link
  const links = document.querySelectorAll('.nav-link:not(.nav-cta)');
  links.forEach(l => {
    const href = l.getAttribute('href');
    if (href && window.location.pathname.endsWith(href)) {
      links.forEach(x => x.classList.remove('active'));
      l.classList.add('active');
    }
  });
});