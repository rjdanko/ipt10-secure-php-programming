<?php
require __DIR__ . '/bootstrap.php';

// Same-origin API: no CORS headers are sent, so other sites cannot read responses.
header('Content-Type: application/json; charset=utf-8');

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '') {
    $selfOrigin = (!empty($_SERVER['HTTPS']) ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? '');
    if ($origin !== $selfOrigin) { fail(403, 'Origin not allowed', true); }
}

$uid = $_SESSION['user_id'] ?? null;
if (!$uid) { fail(401, 'Login required', true); }

try {
    $db = db(true);

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $stmt = $db->prepare('SELECT id, user_id, title, body FROM notes WHERE user_id = ?');
        $stmt->execute([$uid]);
        echo json_encode($stmt->fetchAll());
        exit;
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (!csrf_ok($_SERVER['HTTP_X_CSRF_TOKEN'] ?? null)) { fail(403, 'Invalid CSRF token', true); }
        if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'application/json') !== 0) { fail(415, 'Content-Type must be application/json', true); }

        $raw = file_get_contents('php://input', false, null, 0, 30001);
        if ($raw === false || strlen($raw) > 30000) { fail(413, 'Request too large', true); }
        try {
            $d = json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            fail(400, 'Invalid JSON', true);
        }
        if (!is_array($d)
            || !is_int($d['id'] ?? null) || $d['id'] < 1
            || !is_string($d['title'] ?? null) || mb_strlen($d['title']) < 1 || mb_strlen($d['title']) > 120
            || !is_string($d['body'] ?? null) || $d['body'] === '' || strlen($d['body']) > 20000) {
            fail(422, 'Invalid fields', true);
        }

        $own = $db->prepare('SELECT 1 FROM notes WHERE id = ? AND user_id = ?');
        $own->execute([$d['id'], $uid]);
        if (!$own->fetch()) { fail(404, 'Not found', true); }

        $stmt = $db->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
        $stmt->execute([$d['title'], $d['body'], $d['id'], $uid]);
        echo json_encode(['updated' => $stmt->rowCount()]);
        exit;
    }

    fail(405, 'Method not supported', true);
} catch (PDOException $ex) {
    error_log('db error ' . $ex->getCode());
    fail(500, 'Something went wrong', true);
}
