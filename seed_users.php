<?php
// Local setup only: run `php seed_users.php` once after importing schema.sql.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

$db = new PDO(
    'mysql:host=localhost;dbname=notes_lab;charset=utf8mb4',
    getenv('LAB_DB_USER') ?: 'root',
    getenv('LAB_DB_PASSWORD') ?: '',
    [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
);

$accounts = [
    'alex@example.test' => 'LabOnly-Alex-123',
    'sam@example.test'  => 'LabOnly-Sam-456',
];
$stmt = $db->prepare('UPDATE users SET password_hash = ? WHERE email = ?');
foreach ($accounts as $email => $password) {
    $stmt->execute([password_hash($password, PASSWORD_DEFAULT), $email]);
    echo "Updated $email\n";
}
