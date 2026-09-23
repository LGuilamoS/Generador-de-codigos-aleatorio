const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();

app.use(express.json());
app.use(cors());

const usuariosDB = [];

app.post('/api/register', async (req, res) => {
    try {
        const { usuario, password } = req.body;
        if (!usuario || !password) {
            return res.status(400).json({ error: 'Faltan campos obligatorios.' });
        }
        const usuarioExiste = usuariosDB.find(u => u.usuario === usuario);
        if (usuarioExiste) {
            return res.status(400).json({ error: 'El nombre de usuario ya está en uso.' });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        usuariosDB.push({ usuario, passwordHash });
        res.status(201).json({ message: 'Usuario registrado exitosamente.' });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { usuario, password } = req.body;
        const userRecord = usuariosDB.find(u => u.usuario === usuario);
        if (!userRecord) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
        }
        const passwordValida = await bcrypt.compare(password, userRecord.passwordHash);
        if (!passwordValida) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
        }
        res.json({ message: 'Inicio de sesión exitoso', usuario: userRecord.usuario });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
