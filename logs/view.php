<?php
session_start();
$configFilePath = '../conn.php';

if (isset($_POST['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ../account/connexion');
    exit();
}

if (!file_exists($configFilePath)) {
    header('Location: ../setdb');
    exit();
}
require_once '../connexion_bdd.php';

function hasPermission($user, $permission) {
    if ($user['permissions'] === '*') {
        return true;
    }
    $userPermissions = explode(',', $user['permissions']);
    return in_array($permission, $userPermissions);
}

if (isset($_SESSION['user_token'])) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
    $stmt->bindParam(':token', $_SESSION['user_token']);
    $stmt->execute();
    $utilisateur = $stmt->fetch();

    if (!$utilisateur) {
        header('Location: ../account/connexion');
        exit();
    }

    if (!hasPermission($utilisateur, 'logs_view')) {
        $_SESSION['error_message'] = "Vous n'avez pas la permission de voir les logs.";
        header('Location: ../settings');
        exit();
    }
} else {
    header('Location: ../account/connexion');
    exit();
}

require_once '../ui/header3.php';
?>

<div class="container mx-auto mt-10 p-6 bg-gray-900 text-white border border-gray-700 rounded-lg shadow-lg">
    <?php
    if (isset($_SESSION['error_message'])) {
        echo '<div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">';
        echo '<strong class="font-bold">Erreur!</strong>';
        echo '<span class="block sm:inline"> ' . $_SESSION['error_message'] . '</span>';
        echo '</div>';
        unset($_SESSION['error_message']);
    }
    ?>
    <div class="grid grid-cols-1 gap-6">
        <div id="logs-view">
            <h2 class="text-3xl font-bold mb-6 text-gray-100 border-b border-gray-600 pb-2">Visualisation des Logs</h2>
            <?php if (hasPermission($utilisateur, 'purge_logs')): ?>
            <form action="purge_logs.php" method="POST">
                <button type="submit" name="purge_logs" class="bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded-lg shadow-lg transition duration-300 ease-in-out">
                    Purger les Logs
                </button>
            </form>
            <?php endif; ?>
            
            <div class="overflow-x-auto mt-4">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead>
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Utilisateur</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Timestamp</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Action</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700">
                        <?php
                        $logsFilePath = 'logs.json';
                        if (file_exists($logsFilePath)) {
                            $logs = file($logsFilePath);
                            foreach ($logs as $log) {
                                $logEntry = json_decode($log, true);
                                echo '<tr>';
                                echo '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">' . htmlspecialchars($logEntry['user']) . '</td>';
                                echo '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">' . htmlspecialchars($logEntry['timestamp']) . '</td>';
                                echo '<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-300">' . htmlspecialchars($logEntry['action']) . '</td>';
                                echo '</tr>';
                            }
                        }
                        ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<?php
require_once '../ui/footer.php';
?>