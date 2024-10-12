<?php
require_once 'connexion_bdd.php';

function ajouter_log($user, $action) {
    global $pdo;
    
    try {
        $stmt = $pdo->prepare("INSERT INTO logs (user, timestamp, action) VALUES (:user, :timestamp, :action)");
        $stmt->execute([
            ':user' => $user,
            ':timestamp' => date('Y-m-d H:i:s'),
            ':action' => $action
        ]);
        return true;
    } catch (PDOException $e) {
        error_log("Erreur lors de l'ajout du log : " . $e->getMessage());
        return false;
    }
}

?>