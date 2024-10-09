<?php
session_start();
$configFilePath = '../conn.php';
if (!file_exists($configFilePath)) {
    header('Location: ../setdb');
    exit();
}
require_once '../connexion_bdd.php';
if (!isset($_SESSION['user_token']) || !isset($_SESSION['user_email'])) {
    header('Location: ../account/connexion');
    exit();
}
$email = $_SESSION['user_email'];
$token = $_SESSION['user_token'];

$stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email AND token = :token");
$stmt->bindParam(':email', $email);
$stmt->bindParam(':token', $token);
$stmt->execute();
$utilisateur = $stmt->fetch();

if (!$utilisateur) {
    header('Location: ../account/connexion');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['json_file'])) {
    // Code d'importation
    if ($_FILES['json_file']['error'] === UPLOAD_ERR_OK) {
        $tempFileName = $_FILES['json_file']['tmp_name'];
        $jsonFile = file_get_contents($tempFileName);
        $importData = json_decode($jsonFile, true);

        foreach ($importData as $table => $rows) {
            if ($table === 'users') {
                continue;
            }
            $stmt = $pdo->prepare("SHOW TABLES LIKE :table");
            $stmt->bindParam(':table', $table);
            $stmt->execute();
            if ($stmt->rowCount() > 0) {
                $pdo->exec("TRUNCATE TABLE $table");

                foreach ($rows as $row) {
                    $existingColumns = [];
                    $columnsStmt = $pdo->prepare("SHOW COLUMNS FROM $table");
                    $columnsStmt->execute();
                    $columnsData = $columnsStmt->fetchAll(PDO::FETCH_COLUMN);

                    foreach ($row as $column => $value) {
                        if (in_array($column, $columnsData)) {
                            $existingColumns[$column] = $value;
                        }
                    }

                    if (!empty($existingColumns)) {
                        $columns = implode(',', array_keys($existingColumns));
                        $placeholders = implode(',', array_fill(0, count($existingColumns), '?'));
                        $stmt = $pdo->prepare("INSERT INTO $table ($columns) VALUES ($placeholders)");
                        $stmt->execute(array_values($existingColumns));
                    }
                }
            }
        }

        if (file_exists($tempFileName)) {
            unlink($tempFileName);
        }
        header('Location: ../settings');
    } else {
        echo 'Error uploading file.';
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'export') {
    // Code d'exportation
    $tables = ['ignored_folders', 'mods', 'options', 'roles', 'users', 'whitelist', 'whitelist_roles'];
    $exportData = [];

    foreach ($tables as $table) {
        $stmt = $pdo->prepare("SELECT * FROM $table");
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        $exportData[$table] = $rows;
    }

    $jsonData = json_encode($exportData, JSON_PRETTY_PRINT);

    header('Content-Type: application/json');
    header('Content-Disposition: attachment; filename="database_export.json"');

    echo $jsonData;
} else {
    header('Location: ../settings');
}
?>