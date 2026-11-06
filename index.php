<?php
require __DIR__ . '/bootstrap.php';

header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'");

try {
    $db = db();
    $action = $_POST['action'] ?? '';
    $message = '';

    if ($action !== '') {
        require_post_csrf();
    }

    if ($action === 'register') {
        $email = trim((string)($_POST['email'] ?? ''));
        $password = (string)($_POST['password'] ?? '');
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
            $message = 'Enter a valid email and a password of at least 8 characters.';
        } else {
            try {
                $hash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $db->prepare("INSERT INTO users (email, password_hash, role) VALUES (?, ?, 'student')");
                $stmt->execute([$email, $hash]);
                $_SESSION['flash'] = 'Account created';
                header('Location: /');
                exit;
            } catch (PDOException $ex) {
                if ($ex->getCode() !== '23000') { throw $ex; }
                $message = 'Registration could not be completed. Try a different email.';
            }
        }
    }

    if ($action === 'login') {
        $stmt = $db->prepare('SELECT * FROM users WHERE email = ?');
        $stmt->execute([(string)($_POST['email'] ?? '')]);
        $user = $stmt->fetch();
        if ($user && password_verify((string)($_POST['password'] ?? ''), $user['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            header('Location: /');
            exit;
        }
        $message = 'Login failed. Check your email and password.';
    }

    $uid = $_SESSION['user_id'] ?? null;

    if ($action === 'save' || $action === 'update') {
        if (!$uid) { fail(403, 'Invalid request'); }
        $title = trim((string)($_POST['title'] ?? ''));
        $body = (string)($_POST['body'] ?? '');
        if ($title === '' || mb_strlen($title) > 120 || $body === '' || strlen($body) > 20000) {
            fail(422, 'Title must be 1-120 characters and body 1-20000 characters.');
        }
        if ($action === 'save') {
            $stmt = $db->prepare('INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)');
            $stmt->execute([$uid, $title, $body]);
        } else {
            $id = (int)($_POST['id'] ?? 0);
            $own = $db->prepare('SELECT 1 FROM notes WHERE id = ? AND user_id = ?');
            $own->execute([$id, $uid]);
            if (!$own->fetch()) { fail(404, 'Not found'); }
            $stmt = $db->prepare('UPDATE notes SET title = ?, body = ? WHERE id = ? AND user_id = ?');
            $stmt->execute([$title, $body, $id, $uid]);
        }
        header('Location: /');
        exit;
    }

    if ($action === 'delete') {
        if (!$uid) { fail(403, 'Invalid request'); }
        $stmt = $db->prepare('DELETE FROM notes WHERE id = ? AND user_id = ?');
        $stmt->execute([(int)($_POST['id'] ?? 0), $uid]);
        if ($stmt->rowCount() === 0) { fail(404, 'Not found'); }
        header('Location: /');
        exit;
    }

    if ($action === 'logout') {
        $_SESSION = [];
        setcookie(session_name(), '', time() - 3600, '/');
        session_destroy();
        header('Location: /');
        exit;
    }

    if ($message === '') {
        $message = $_SESSION['flash'] ?? '';
    }
    unset($_SESSION['flash']);
    $notes = [];
    $editing = false;
    $role = '';
    if ($uid) {
        $stmt = $db->prepare('SELECT role FROM users WHERE id = ?');
        $stmt->execute([$uid]);
        $role = (string)$stmt->fetchColumn();
        $stmt = $db->prepare('SELECT id, title, body FROM notes WHERE user_id = ? ORDER BY id DESC');
        $stmt->execute([$uid]);
        $notes = $stmt->fetchAll();
        if (isset($_GET['edit'])) {
            $stmt = $db->prepare('SELECT id, title, body FROM notes WHERE id = ? AND user_id = ?');
            $stmt->execute([(int)$_GET['edit'], $uid]);
            $editing = $stmt->fetch();
            if (!$editing) { fail(404, 'Not found'); }
        }
    }
} catch (PDOException $ex) {
    error_log('db error ' . $ex->getCode());
    fail(500, 'Something went wrong');
}
$csrf = $_SESSION['csrf'];
?>
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Campus Notes</title>
<style>body{font:16px sans-serif;max-width:750px;margin:2rem auto}label{display:block;margin:.5rem 0}article{border:1px solid #aaa;padding:1rem;margin:1rem 0}</style>
</head>
<body>
<h1>Campus Notes</h1>
<p><?= e($message) ?></p>
<?php if (!$uid): ?>
<h2>Register or sign in</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <label>Email <input name="email" type="email" required></label>
  <label>Password <input name="password" type="password" required minlength="8"></label>
  <button name="action" value="register">Register</button>
  <button name="action" value="login">Sign in</button>
</form>
<?php else: ?>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  User ID: <?= e($uid) ?> | Role: <?= e($role) ?> |
  <button name="action" value="logout">Log out</button>
</form>
<?php if ($editing): ?>
<h2>Edit note</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <input type="hidden" name="id" value="<?= e($editing['id']) ?>">
  <label>Title <input name="title" value="<?= e($editing['title']) ?>" required maxlength="120"></label>
  <label>Body <textarea name="body" required maxlength="20000"><?= e($editing['body']) ?></textarea></label>
  <button name="action" value="update">Update</button>
  <a href="/">Cancel</a>
</form>
<?php endif; ?>
<h2>Create a note</h2>
<form method="post">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <label>Title <input name="title" required maxlength="120"></label>
  <label>Body <textarea name="body" required maxlength="20000"></textarea></label>
  <button name="action" value="save">Save</button>
</form>
<h2>Notes</h2>
<?php foreach ($notes as $note): ?>
<article><h3><?= e($note['title']) ?></h3><p><?= e($note['body']) ?></p>
<a href="?edit=<?= e($note['id']) ?>">Edit</a>
<form method="post" style="display:inline">
  <input type="hidden" name="csrf" value="<?= e($csrf) ?>">
  <input type="hidden" name="id" value="<?= e($note['id']) ?>">
  <button name="action" value="delete">Delete</button>
</form></article>
<?php endforeach; ?>
<?php endif; ?>
</body></html>
