// Importamos las bibliotecas necesarias
const express = require('express'); // framework para crear el servidor web
const bcrypt = require('bcryptjs'); // para encriptar las contraseñas
const jwt = require('jsonwebtoken'); // para crear y verificar tokens de autenticación
const bodyParser = require('body-parser'); // para analizar los cuerpos de las solicitudes

// Configuración del servidor
const app = express();
const PORT = 3000;

// Middleware para analizar datos JSON en el cuerpo de las solicitudes
app.use(bodyParser.json());

// Simulación de base de datos para almacenar usuarios temporalmente
let usersDB = [];

// Clave secreta para firmar el token (en producción, mantener en variables de entorno)
const SECRET_KEY = 'your_secret_key';

// Endpoint de registro de usuarios
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Validación de datos
    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    // Verificación de usuario existente
    const existingUser = usersDB.find(user => user.username === username);
    if (existingUser) {
        return res.status(400).json({ error: 'El usuario ya existe' });
    }

    // Encriptación de la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Almacenamiento del usuario en la "base de datos"
    usersDB.push({ username, password: hashedPassword });
    res.status(201).json({ message: 'Registro exitoso' });
});

// Endpoint de inicio de sesión
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Validación de datos
    if (!username || !password) {
        return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
    }

    // Verificación del usuario en la "base de datos"
    const user = usersDB.find(user => user.username === username);
    if (!user) {
        return res.status(400).json({ error: 'Error en la autenticación' });
    }

    // Comparación de la contraseña proporcionada con la almacenada
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({ error: 'Error en la autenticación' });
    }

    // Generación del token JWT si la autenticación es correcta
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ message: 'Autenticación satisfactoria', token });
});

// Iniciamos el servidor en el puerto especificado
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
