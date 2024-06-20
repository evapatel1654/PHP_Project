<?php
$server = "localhost";
$username = "root";
$password = "";
$dbname = "userdb";

$conn = new mysqli($server, $username, $password, $dbname);


if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = $_POST['username']; 
    $email = $_POST['email'];
    $pwd = $_POST['password'];

    if (isset($_POST['email']) && isset($_POST['username']) && isset($_POST['password'])) {
        $hashed_password = password_hash($pwd, PASSWORD_DEFAULT);

        $sql = "INSERT INTO user (email, username, pwd) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("sss", $email, $username, $hashed_password);

        if ($stmt->execute()) {
            echo "Registration successful!";
        } else {
            echo "Error: " . $sql . "<br>" . $conn->error;
        }

        $stmt->close();
    } else {
        echo "Please fill out all fields (email, username, password).";
    }
}

$conn->close();