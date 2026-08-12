<?php
session_start();

if (!isset($_SESSION['admin']) || $_SESSION['admin'] !== true) {
    header("Location: login.php");
    exit;
}
?>

<h1>Vítej v administraci!</h1>
<a href="logout.php">Odhlásit</a>
