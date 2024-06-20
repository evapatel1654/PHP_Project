<?php
require 'db.php'; 

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = $_POST['email'];
    $new_password = password_hash($_POST['new_password'], PASSWORD_BCRYPT);


    $query = $pdo->prepare("SELECT * FROM user WHERE email = :email");
    $query->execute(['email' => $email]);
    $user = $query->fetch();

    if ($user) {
        $query = $pdo->prepare("UPDATE user SET pwd = :pwd WHERE email = :email");
        $query->execute(['pwd' => $new_password, 'email' => $email]);

        echo json_encode(['status' => 'success', 'message' => 'Password has been reset successfully.']);
    } else {
        echo json_encode(['status' => 'error', 'message' => 'Email not found.']);
    }
}
?>
