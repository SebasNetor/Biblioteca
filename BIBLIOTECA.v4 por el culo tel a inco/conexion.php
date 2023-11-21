<?php
// Iniciar la sesión (si no está iniciada)
session_start();

// Conectar a la base de datos (ajusta las credenciales según tu configuración)
$servername = "localhost";
$username = "root";
$password = "Yeron100";
$dbname = "Biblioteca";

$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar la conexión
if ($conn->connect_error) {
    die("Error de conexión a la base de datos: " . $conn->connect_error);
}

// Procesar el formulario de registro
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['nombre_usuario_registrar']) && isset($_POST['contrasena_registrar'])) {
    $nombre_usuario = $_POST['nombre_usuario_registrar'];
    $contrasena = $_POST['contrasena_registrar'];

    // Hashear la contraseña antes de almacenarla (debes usar una función segura)
    $contrasena_hasheada = password_hash($contrasena, PASSWORD_BCRYPT);

    // Insertar los datos en la base de datos (asegúrate de proteger contra inyección SQL)
    $stmt = $conn->prepare("INSERT INTO usuarios (nombre_usuario, contrasena) VALUES (?, ?)");
    $stmt->bind_param("ss", $nombre_usuario, $contrasena_hasheada);

    if ($stmt->execute()) {
        echo "Registro exitoso. Puedes iniciar sesión ahora.";
    } else {
        echo "Error al registrar el usuario.";
    }

    $stmt->close();
}

// Procesar el formulario de inicio de sesión
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['nombre_usuario_login']) && isset($_POST['contrasena_login'])) {
    $nombre_usuario = $_POST['nombre_usuario_login'];
    $contrasena = $_POST['contrasena_login'];

    // Buscar al usuario en la base de datos
    $stmt = $conn->prepare("SELECT contrasena FROM usuarios WHERE nombre_usuario = ?");
    $stmt->bind_param("s", $nombre_usuario);
    $stmt->execute();
    $stmt->bind_result($contrasena_guardada);
    $stmt->fetch();
    $stmt->close();

    // Verificar la contraseña ingresada con la guardada en la base de datos
    if (password_verify($contrasena, $contrasena_guardada)) {
        $_SESSION['nombre_usuario'] = $nombre_usuario; // Iniciar sesión

        // Redirigir a la página de la biblioteca o a donde desees
        header("Location: biblioteca.php");
    } else {
        echo "Nombre de usuario o contraseña incorrectos.";
    }
}

// Cerrar la conexión a la base de datos
$conn->close();
?>
