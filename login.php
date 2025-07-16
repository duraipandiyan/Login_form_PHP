<?php
include "login.html";
include 'config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['login'])) {
    $uname = trim($_POST['username']);
    $pass = $_POST['password'];

    if (empty($uname) || empty($pass)) {
        echo "<div class='alert alert-warning'> Please fill in all fields.</div>";
    } else {
        $sql = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $uname);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 1) {
            $row = $result->fetch_assoc();
            if (password_verify($pass, $row['password'])) {
                header("Location: home.php"); 
                exit(); 
            } else {
                echo "<div class='alert alert-danger'> Incorrect password.</div>";
            }
        } else {
            echo "<div class='alert alert-danger'> Username not found.</div>";
        }
        $stmt->close(); 
    }
}

$conn->close();
?>