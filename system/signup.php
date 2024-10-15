<?php
session_start();

// ตั้งค่าการเชื่อมต่อฐานข้อมูล
$servername = "localhost";
$db_username = "root";
$db_password = "";
$dbname = "login_system";

$conn = new mysqli($servername, $db_username, $db_password, $dbname);

// ตรวจสอบการเชื่อมต่อ
if ($conn->connect_error) {
    die("การเชื่อมต่อล้มเหลว: " . $conn->connect_error);
}

// ตรวจสอบว่าฟอร์มถูกส่งมาหรือไม่
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // รับค่าจากฟอร์ม
    $id_card_number = trim($_POST['id_card_number']);
    $full_name = trim($_POST['full_name']);
    $gender = trim($_POST['gender']);
    $age = trim($_POST['age']);
    $address = trim($_POST['address']);
    $province = trim($_POST['province']);
    $postal_code = trim($_POST['postal_code']);
    $phone = trim($_POST['phone']);
    $email = trim($_POST['email']);
    $username = trim($_POST['username']);
    $password = trim($_POST['password']); // รับรหัสผ่านจากฟอร์ม

    // เข้ารหัสรหัสผ่านก่อนบันทึกลงในฐานข้อมูล
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);

    // ตรวจสอบว่าชื่อผู้ใช้, อีเมล หรือเลขบัตรประชาชนมีอยู่แล้วในระบบหรือไม่
    $check_sql = "SELECT * FROM users WHERE username = ? OR email = ? OR id_card_number = ?";
    $stmt_check = $conn->prepare($check_sql);
    $stmt_check->bind_param("sss", $username, $email, $id_card_number);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();

    if ($result_check->num_rows > 0) {
        $_SESSION['error'] = "ชื่อผู้ใช้, อีเมลล์, หรือเลขบัตรประชาชนนี้มีอยู่แล้วในระบบ";
        header("Location: register.php");
        exit();
    }

    // บันทึกข้อมูลผู้ใช้ลงในฐานข้อมูล
    $sql = "INSERT INTO users (id_card_number, full_name, gender, age, address, province, postal_code, phone, email, username, password) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssisisssss", $id_card_number, $full_name, $gender, $age, $address, $province, $postal_code, $phone, $email, $username, $hashed_password);

    if ($stmt->execute()) {
        $_SESSION['success'] = "สมัครสมาชิกสำเร็จ";
        header("Location: register.php");
        exit();
    } else {
        $_SESSION['error'] = "เกิดข้อผิดพลาดในการสมัครสมาชิก";
        header("Location: register.php");
        exit();
    }

    $stmt->close();
    $stmt_check->close();
    $conn->close();
}
?>
