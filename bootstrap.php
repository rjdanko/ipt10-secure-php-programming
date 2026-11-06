<?php
// Shared setup for index.php and api.php: error handling, session, database, CSRF, escaping.

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => !empty($_SERVER['HTTPS']),
]);
session_start();
$_SESSION['csrf'] ??= bin2hex(random_bytes(32));

function e($s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function fail(int $code, string $message, bool $json = false): never {
    http_response_code($code);
    if ($json) {
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => $message]);
    } else {
        echo e($message);
    }
    exit;
}

function db(bool $json = false): PDO {
    $user = getenv('LAB_DB_USER');
    $pass = getenv('LAB_DB_PASSWORD');
    if (!$user || $pass === false) {
        error_log('LAB_DB_USER / LAB_DB_PASSWORD not set');
        fail(500, 'Server not configured', $json);
    }
    try {
        return new PDO('mysql:host=localhost;dbname=notes_lab;charset=utf8mb4', $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    } catch (PDOException $ex) {
        error_log('db connect error ' . $ex->getCode());
        fail(500, 'Something went wrong', $json);
    }
}

function csrf_ok(?string $token): bool {
    return is_string($token) && hash_equals($_SESSION['csrf'], $token);
}

function require_post_csrf(): void {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !csrf_ok($_POST['csrf'] ?? null)) {
        fail(403, 'Invalid request');
    }
}
