/* contact.js — Contact page form handler */

function submitForm() {
  const first   = document.getElementById('f-first').value.trim();
  const last    = document.getElementById('f-last').value.trim();
  const email   = document.getElementById('f-email').value.trim();
  const subject = document.getElementById('f-subject').value;
  const message = document.getElementById('f-message').value.trim();
  const status  = document.getElementById('form-status');

  status.classList.remove('hidden', 'ok', 'error');

  if (!first || !last || !email || !subject || !message) {
    status.className = 'mb-4 error';
    status.textContent = 'Please complete all fields before submitting.';
    return;
  }

  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRe.test(email)) {
    status.className = 'mb-4 error';
    status.textContent = 'Please enter a valid email address.';
    return;
  }

  // Simulate submission (replace with real API call when backend endpoint is ready)
  status.className = 'mb-4 ok';
  status.textContent = `Thank you, ${first}. Your message has been received. We'll be in touch within one business day.`;

  ['f-first','f-last','f-email','f-company','f-subject','f-message'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
}