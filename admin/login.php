<?php
session_start();

// Pokud už je přihlášený, pošli ho do adminu
if (isset($_SESSION['admin']) && $_SESSION['admin'] === true) {
    header("Location: admin.php");
    exit;
}
?>

<form method="POST" action="login_check.php">
    <label>Heslo:</label>
    <input type="password" name="password" required>
    <button type="submit">Přihlásit</button>
</form>
