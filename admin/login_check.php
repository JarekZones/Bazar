<?php
session_start();

// Nastav si vlastní heslo
$correct_password = "TvojeHeslo123"; // změň si!

if ($_POST['password'] === $correct_password) {
    $_SESSION['admin'] = true;
    header("Location: admin.php");
    exit;
} else {
    echo "Špatné heslo!";
}
