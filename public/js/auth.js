/**
 * auth.js — Client-side helpers for auth forms.
 * No external libraries. Plain, minimal JavaScript.
 */

/** Toggle password field visibility */
function togglePwd(fieldId) {
  const field = document.getElementById(fieldId);
  if (!field) return;
  field.type = field.type === 'password' ? 'text' : 'password';
}

/** Password strength indicator */
(function () {
  const pwd = document.getElementById('password');
  const bar = document.getElementById('strengthBar');
  if (!pwd || !bar) return;

  pwd.addEventListener('input', function () {
    const v = pwd.value;
    let score = 0;
    if (v.length >= 8)  score++;
    if (v.length >= 12) score++;
    if (/[A-Z]/.test(v)) score++;
    if (/[a-z]/.test(v)) score++;
    if (/[0-9]/.test(v)) score++;
    if (/[^A-Za-z0-9]/.test(v)) score++;

    const pct = Math.min(100, Math.round((score / 6) * 100));
    const color = score <= 2 ? '#ef4444' : score <= 4 ? '#f59e0b' : '#22c55e';
    bar.style.width = pct + '%';
    bar.style.background = color;
    bar.style.height = '4px';
  });
})();

/** Auto-advance OTP input: allow only digits */
(function () {
  const otp = document.querySelector('.otp-input');
  if (!otp) return;
  otp.addEventListener('input', function () {
    this.value = this.value.replace(/\D/g, '').slice(0, 6);
  });
})();

