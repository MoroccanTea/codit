/* Customer portal - second factor page (served to the browser). */
(function () {
  'use strict';

  var form = document.getElementById('otp-form');
  var expected = null;

  async function requestCode() {
    var res = await fetch('/api/v1/auth/otp/send', { method: 'POST', credentials: 'include' });
    var data = await res.json();
    expected = data.otp;
    document.getElementById('status').textContent = 'Code sent';
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var entered = document.getElementById('otp').value.trim();

    // codit-expect: CWE-308 OTP compared in browser JavaScript, the server never checks it
    if (entered === expected) {
      document.getElementById('status').textContent = 'Verified';
      document.getElementById('otp').disabled = true;
      // codit-expect: CWE-308,CWE-807 2FA completion flag kept in localStorage and trusted by the SPA
      localStorage.setItem('mfaVerified', 'true');
      window.location.href = '/dashboard';
    } else {
      document.getElementById('status').textContent = 'Wrong code';
    }
  });

  document.getElementById('resend').addEventListener('click', requestCode);
  requestCode();
})();
