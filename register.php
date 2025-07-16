<?php

session_start();

include "register.html";
include 'config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['sign-up'])) {
    $uname = trim($_POST['username']);
    $pass = $_POST['password'];
    $cpass = $_POST['cpassword'];
    $email = trim($_POST['email']);
    $phone = trim($_POST['phone']);

    // Validation
    if ($pass !== $cpass) {
        echo "<div class='alert alert-danger'> Passwords do not match.</div>";
    } elseif (strlen($pass) < 6) {
        echo "<div class='alert alert-danger'> Password must be at least 6 characters.</div>";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<div class='alert alert-danger'> Invalid email format.</div>";
    } elseif (!preg_match('/^\d{10}$/', $phone)) {
        echo "<div class='alert alert-danger'> Phone number must be 10 digits.</div>";
    } else {
        
        $duplicate_check_sql = "SELECT username, email, phone FROM users WHERE username = ? OR email = ? OR phone = ?";
        $stmt_check = $conn->prepare($duplicate_check_sql);
        $stmt_check->bind_param("sss", $uname, $email, $phone);
        $stmt_check->execute();
        $result_check = $stmt_check->get_result();

        if ($result_check->num_rows > 0) {
            $row_check = $result_check->fetch_assoc();
            if ($row_check['username'] === $uname) {
                echo "<div class='alert alert-danger'> Username already exists. Please choose a different one.</div>";
            } elseif ($row_check['email'] === $email) {
                echo "<div class='alert alert-danger'> Email already registered.</div>";
            } elseif ($row_check['phone'] === $phone) {
                echo "<div class='alert alert-danger'> Phone number already registered.</div>";
            }
        } else {
            $hashed_pass = password_hash($pass, PASSWORD_DEFAULT);

            $sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ssss", $uname, $hashed_pass, $email, $phone);

            if ($stmt->execute()) {
                $_SESSION['registration_success_message'] = "Congratulations! You have successfully registered. Please log in.";

                
                header("Location: login.php"); 
                exit();
            } else {
                echo "<div class='alert alert-danger'>Error: " . $stmt->error . "</div>";
            }
            $stmt->close();
        }
        $stmt_check->close();
    }
}

$conn->close();
?>