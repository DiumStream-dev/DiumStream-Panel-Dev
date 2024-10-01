<?php
session_start();
$configFilePath = '../../conn.php';
if (!file_exists($configFilePath)) {
    header('Location: ../../setdb');
    exit();
}
require_once '../../connexion_bdd.php';

function ajouter_log($user, $action) {
    $logsFilePath = '../../logs/logs.json';
    $logEntry = [
        'user' => $user,
        'timestamp' => date('Y-m-d H:i:s'),
        'action' => $action
    ];
    $logJson = json_encode($logEntry) . "\n";
    file_put_contents($logsFilePath, $logJson, FILE_APPEND);
}

if (isset($_POST['logout'])) {
    ajouter_log($_SESSION['user_email'], "Déconnexion");
    session_unset();
    session_destroy();
    header('Location: ../connexion');
    exit();
}

if (isset($_SESSION['user_token'])) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE token = :token");
    $stmt->bindParam(':token', $_SESSION['user_token']);
    $stmt->execute();
    $utilisateur = $stmt->fetch();

    if (!$utilisateur) {
        header('Location: ../connexion');
        exit();
    }
} else {
    header('Location: ../connexion');
    exit();
}

$message = '';

if (isset($_POST['submit'])) {
    $email = trim($_POST['email']);
    $password = trim($_POST['password']);
    $confirm_password = trim($_POST['confirm_password']);

    $errors = array();

    if (empty($email) || empty($password) || empty($confirm_password)) {
        $errors[] = "Tous les champs sont obligatoires.";
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Adresse email invalide.";
    }

    if ($password !== $confirm_password) {
        $errors[] = "Les mots de passe ne correspondent pas.";
    }

    $query = "SELECT id FROM users WHERE email = :email";
    $stmt = $pdo->prepare($query);
    $stmt->execute(array('email' => $email));

    if ($stmt->rowCount() > 0) {
        $errors[] = "Adresse email déjà utilisée.";
    }

    if (count($errors) === 0) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);

        $query = "INSERT INTO users (email, password) VALUES (:email, :password)";
        $stmt = $pdo->prepare($query);

        $stmt->execute(array(
            'email' => $email,
            'password' => $hashed_password
        ));

        $message = "Utilisateur ajouté avec succès.";
        ajouter_log($_SESSION['user_email'], "Ajout de l'utilisateur: $email");
    }
}

if (isset($_POST['delete_user'])) {
    $user_id = $_POST['user_id'];
    $user_email = $_POST['user_email'];
    
    if ($user_id != 1) {
        $query = "DELETE FROM users WHERE id = :id";
        $stmt = $pdo->prepare($query);
        $stmt->execute(array('id' => $user_id));
        
        $message = "Utilisateur supprimé avec succès.";
        ajouter_log($_SESSION['user_email'], "Suppression de l'utilisateur: $user_email");
    } else {
        $message = "Impossible de supprimer l'utilisateur principal.";
    }
}

if (isset($_POST['change_password'])) {
    $user_id = $_POST['user_id'];
    $new_password = $_POST['new_password'];
    $confirm_new_password = $_POST['confirm_new_password'];

    if ($new_password === $confirm_new_password) {
        if ($user_id != 1) {
            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
            $query = "UPDATE users SET password = :password WHERE id = :id";
            $stmt = $pdo->prepare($query);
            $stmt->execute(array('password' => $hashed_password, 'id' => $user_id));
            
            $message = "Mot de passe changé avec succès.";
            ajouter_log($_SESSION['user_email'], "Changement de mot de passe pour l'utilisateur ID: $user_id");
        } else {
            $message = "Impossible de changer le mot de passe de l'utilisateur principal ici.";
        }
    } else {
        $message = "Les nouveaux mots de passe ne correspondent pas.";
    }
}

$stmt = $pdo->prepare("SELECT id, email FROM users");
$stmt->execute();
$users = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>
<!DOCTYPE html>
<html lang="fr" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Gestion des utilisateurs</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 1000;
        }
        .overlay-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background-color: #1f2937;
            padding: 2rem;
            border-radius: 0.5rem;
        }
    </style>
</head>

<?php require_once '../../ui/header2.php'; ?>

<body class="bg-gray-900 text-white">
    <div class="container mx-auto mt-20 p-6 bg-gray-900 text-white border border-gray-700 rounded-lg shadow-lg">
        <div class="flex justify-center">
            <div class="w-full max-w-md">
                <h2 class="text-3xl font-bold mb-6 text-center">Ajouter un utilisateur</h2>
                <?php if (!empty($message)) : ?>
                    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative mb-4">
                        <?php echo $message; ?>
                    </div>
                <?php endif; ?>
                <?php if (isset($errors) && count($errors) > 0) : ?>
                    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4">
                        <ul>
                            <?php foreach ($errors as $error) : ?>
                                <li><?php echo $error; ?></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
                <form method="post" action="">
                    <div class="mb-4">
                        <label for="email" class="block text-gray-400 text-sm font-medium mb-2">E-mail :</label>
                        <div class="relative">
                            <input type="email" name="email" id="email" class="form-input mt-1 block w-full rounded-lg border-gray-600 bg-gray-700 text-gray-200 p-2 focus:ring-indigo-500 focus:border-indigo-500" required>
                            <i class="bi bi-envelope-fill absolute right-3 top-2.5 text-gray-400"></i>
                        </div>
                    </div>
                    <div class="mb-4">
                        <label for="password" class="block text-gray-400 text-sm font-medium mb-2">Mot de passe :</label>
                        <div class="relative">
                            <input type="password" name="password" id="password" class="form-input mt-1 block w-full rounded-lg border-gray-600 bg-gray-700 text-gray-200 p-2 focus:ring-indigo-500 focus:border-indigo-500" required>
                            <i class="bi bi-lock-fill absolute right-10 top-2.5 text-gray-400"></i>
                            <i id="togglePassword" class="bi bi-eye-fill absolute right-3 top-2.5 cursor-pointer text-gray-400"></i>
                        </div>
                    </div>
                    <div class="mb-4">
                        <label for="confirm_password" class="block text-gray-400 text-sm font-medium mb-2">Confirmez le mot de passe :</label>
                        <div class="relative">
                            <input type="password" name="confirm_password" id="confirm_password" class="form-input mt-1 block w-full rounded-lg border-gray-600 bg-gray-700 text-gray-200 p-2 focus:ring-indigo-500 focus:border-indigo-500" required>
                            <i class="bi bi-lock-fill absolute right-10 top-2.5 text-gray-400"></i>
                            <i id="toggleConfirmPassword" class="bi bi-eye-fill absolute right-3 top-2.5 cursor-pointer text-gray-400"></i>
                        </div>
                    </div>
                    <div class="flex items-center justify-center">
                        <button type="submit" name="submit" class="bg-indigo-500 text-white py-2 px-4 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-opacity-50">
                            Ajouter
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    <div class="container mx-auto mt-10 p-6 bg-gray-800 text-white border border-gray-700 rounded-lg shadow-lg">
        <h2 class="text-3xl font-bold mb-6 text-center">Liste des utilisateurs</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <?php foreach ($users as $user) : ?>
                <div class="p-4 bg-gray-900 rounded-lg shadow-md">
                    <h3 class="text-lg font-medium mb-2"><?php echo htmlspecialchars($user['email']); ?></h3>
                    <?php if ($user['id'] != 1) : ?>
                        <div class="flex justify-between items-center">
                            <form method="post" action="" class="inline-block" onsubmit="return confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ?');">
                                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                <input type="hidden" name="user_email" value="<?php echo $user['email']; ?>">
                                <button type="submit" name="delete_user" class="bg-red-500 text-white py-1 px-2 rounded-lg hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-opacity-50">
                                    Supprimer
                                </button>
                            </form>
                            <button onclick="showChangePasswordOverlay(<?php echo $user['id']; ?>)" class="bg-yellow-500 text-white py-1 px-2 rounded-lg hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-yellow-500 focus:ring-opacity-50">
                                Changer le mot de passe
                            </button>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
    </div>
    
    <div id="changePasswordOverlay" class="overlay">
        <div class="overlay-content">
            <h3 class="text-xl font-bold mb-4">Changer le mot de passe</h3>
            <form method="post" action="" id="changePasswordForm">
                <input type="hidden" name="user_id" id="changePasswordUserId">
                <input type="password" name="new_password" placeholder="Nouveau mot de passe" class="form-input mt-1 block w-full rounded-lg border-gray-600 bg-gray-700 text-gray-200 p-2 focus:ring-indigo-500 focus:border-indigo-500" required>
                <input type="password" name="confirm_new_password" placeholder="Confirmer le mot de passe" class="form-input mt-1 block w-full rounded-lg border-gray-600 bg-gray-700 text-gray-200 p-2 focus:ring-indigo-500 focus:border-indigo-500 mt-2" required>
                <div class="flex justify-between mt-4">
                    <button type="submit" name="change_password" class="bg-green-500 text-white py-1 px-2 rounded-lg hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-50">
                        Confirmer
                    </button>
                    <button type="button" onclick="hideChangePasswordOverlay()" class="bg-gray-500 text-white py-1 px-2 rounded-lg hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500 focus:ring-opacity-50">
                        Annuler
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function showChangePasswordOverlay(userId) {
            document.getElementById('changePasswordUserId').value = userId;
            document.getElementById('changePasswordOverlay').style.display = 'block';
        }

        function hideChangePasswordOverlay() {
            document.getElementById('changePasswordOverlay').style.display = 'none';
        }

        const togglePassword = document.querySelector('#togglePassword');
        const password = document.querySelector('#password');
        const toggleConfirmPassword = document.querySelector('#toggleConfirmPassword');
        const confirmPassword = document.querySelector('#confirm_password');

        togglePassword.addEventListener('click', function(e) {
            const type = password.getAttribute('type') === 'password' ? 'text' : 'password';
            password.setAttribute('type', type);
            this.classList.toggle('bi-eye-fill');
            this.classList.toggle('bi-eye-slash-fill');
        });

        toggleConfirmPassword.addEventListener('click', function(e) {
            const type = confirmPassword.getAttribute('type') === 'password' ? 'text' : 'password';
            confirmPassword.setAttribute('type', type);
            this.classList.toggle('bi-eye-fill');
            this.classList.toggle('bi-eye-slash-fill');
        });
    </script>
    <?php require_once '../../ui/footer.php'; ?>
</body>
</html>