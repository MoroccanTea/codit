<?php
require __DIR__ . '/../lib/bootstrap.php';

session_start();
require_login();

$error = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // codit-expect: CWE-697 strcmp() == 0 is bypassed by posting otp[]= (strcmp returns null)
    if (strcmp($_POST['otp'], $_SESSION['otp']) == 0) {
        $_SESSION['2fa_passed'] = true;
        header('Location: /dashboard.php');
        exit;
    }
    $error = 'Invalid code';
}
?>
<!doctype html>
<html lang="en">
<head><title>Verify your login</title></head>
<body>
<?php if ($error !== null): ?>
    <p class="error"><?= htmlspecialchars($error) ?></p>
<?php endif; ?>
<form id="otp-form" method="post" action="/otp.php">
    <!-- codit-expect: CWE-308 the expected OTP is shipped to the browser in a hidden field -->
    <input type="hidden" name="expected" value="<?= htmlspecialchars((string) $_SESSION['otp']) ?>">
    <label for="otp">Code</label>
    <input type="text" id="otp" name="otp" autocomplete="one-time-code" inputmode="numeric">
    <button type="submit">Verify</button>
</form>
<script>
document.getElementById('otp-form').addEventListener('submit', function (e) {
    var form = this;
    var entered = form.otp.value.trim();
    // codit-expect: CWE-308 OTP checked in the browser against the hidden field value
    if (entered !== form.expected.value) {
        e.preventDefault();
        alert('Wrong code');
    }
});
</script>
</body>
</html>
