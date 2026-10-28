<?php

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function answer(int $status, array $body): never
{
    http_response_code($status);

    echo json_encode(
        $body,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

function input(): array
{
    $raw = file_get_contents('php://input');

    if ($raw === false || strlen($raw) > 16384) {
        answer(400, [
            'valid' => false,
            'message' => 'Некорректный запрос.'
        ]);
    }

    $data = json_decode($raw, true);

    if (!is_array($data)) {
        answer(400, [
            'valid' => false,
            'message' => 'Ожидался JSON.'
        ]);
    }

    return $data;
}

function db(): PDO
{
    $path = getenv('PIXELFORGE_DB');

    if (!$path || !is_dir(dirname($path))) {
        answer(500, [
            'valid' => false,
            'message' => 'Не настроен путь к базе данных.'
        ]);
    }

    $pdo = new PDO('sqlite:' . $path);

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);

    $pdo->exec('PRAGMA busy_timeout = 5000');

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            expires TEXT NULL,
            created_at TEXT NOT NULL
        )'
    );

    return $pdo;
}

function parseDate(string $value): ?string
{
    if ($value === '') {
        return null;
    }

    $date = DateTimeImmutable::createFromFormat(
        '!d.m.Y',
        $value,
        new DateTimeZone('UTC')
    );

    $errors = DateTimeImmutable::getLastErrors();

    if (
        $date === false ||
        ($errors !== false &&
            ($errors['warning_count'] > 0 ||
             $errors['error_count'] > 0)) ||
        $date->format('d.m.Y') !== $value
    ) {
        answer(400, [
            'valid' => false,
            'message' => 'Используй формат ДД.ММ.ГГГГ.'
        ]);
    }

    $today = new DateTimeImmutable('today', new DateTimeZone('UTC'));

    if ($date < $today) {
        answer(400, [
            'valid' => false,
            'message' => 'Дата окончания уже прошла.'
        ]);
    }

    return $date->format('Y-m-d');
}

function expired(?string $value): bool
{
    if ($value === null) {
        return false;
    }

    $date = DateTimeImmutable::createFromFormat(
        '!Y-m-d',
        $value,
        new DateTimeZone('UTC')
    );

    if ($date === false) {
        return true;
    }

    $today = new DateTimeImmutable('today', new DateTimeZone('UTC'));

    return $today > $date;
}

function displayDate(?string $value): ?string
{
    if ($value === null) {
        return null;
    }

    $date = DateTimeImmutable::createFromFormat(
        '!Y-m-d',
        $value,
        new DateTimeZone('UTC')
    );

    return $date ? $date->format('d.m.Y') : null;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');

    answer(405, [
        'valid' => false,
        'message' => 'Используй POST.'
    ]);
}

$data = input();
$action = $data['action'] ?? null;

try {
    $pdo = db();

    if ($action === 'verify') {
        $key = $data['key'] ?? '';

        if (!is_string($key) || $key === '' || strlen($key) > 256) {
            answer(400, [
                'valid' => false,
                'message' => 'Некорректный ключ.'
            ]);
        }

        $hash = hash('sha256', $key);

        $stmt = $pdo->prepare(
            'SELECT expires FROM licenses WHERE key_hash = :hash'
        );

        $stmt->execute([':hash' => $hash]);

        $license = $stmt->fetch();

        if ($license === false) {
            answer(200, [
                'valid' => false,
                'message' => 'Ключ не найден.'
            ]);
        }

        $expiry = $license['expires'];

        if (expired($expiry)) {
            answer(200, [
                'valid' => false,
                'message' => 'Срок действия лицензии истёк.'
            ]);
        }

        answer(200, [
            'valid' => true,
            'expires' => displayDate($expiry),
            'message' => 'Лицензия действительна.'
        ]);
    }

    if ($action === 'create') {
        $expected = getenv('PIXELFORGE_ADMIN_TOKEN');
        $provided = $data['admin_token'] ?? '';

        if (
            !$expected ||
            !is_string($provided) ||
            !hash_equals($expected, $provided)
        ) {
            answer(403, [
                'valid' => false,
                'message' => 'Доступ запрещён.'
            ]);
        }

        $key = $data['key'] ?? '';
        $date = $data['expires'] ?? '';

        if (
            !is_string($key) ||
            !preg_match('/\A[A-Za-z0-9]{8,128}\z/', $key)
        ) {
            answer(400, [
                'valid' => false,
                'message' => 'Ключ должен содержать 8–128 букв или цифр.'
            ]);
        }

        if (!is_string($date)) {
            answer(400, [
                'valid' => false,
                'message' => 'Некорректная дата.'
            ]);
        }

        $expiry = parseDate($date);

        try {
            $stmt = $pdo->prepare(
                'INSERT INTO licenses (key_hash, expires, created_at)
                 VALUES (:hash, :expiry, :created)'
            );

            $stmt->execute([
                ':hash' => hash('sha256', $key),
                ':expiry' => $expiry,
                ':created' => gmdate('c')
            ]);
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') {
                answer(409, [
                    'valid' => false,
                    'message' => 'Такой ключ уже существует.'
                ]);
            }

            throw $e;
        }

        answer(201, [
            'valid' => true,
            'message' => 'Лицензия создана.',
            'expires' => displayDate($expiry)
        ]);
    }

    answer(400, [
        'valid' => false,
        'message' => 'Неизвестное действие.'
    ]);

} catch (Throwable $e) {
    error_log('PixelForge API: ' . $e->getMessage());

    answer(500, [
        'valid' => false,
        'message' => 'Внутренняя ошибка сервера.'
    ]);
}