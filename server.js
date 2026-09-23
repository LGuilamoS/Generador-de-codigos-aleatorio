const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');

const app = express();

app.use(express.json());
app.use(cors());

// CONEXIÓN A MONGODB ATLAS (Recuerda cambiar TU_CONTRASEÑA_REAL por la contraseña que creaste)
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://luigiguilamo_db_user:<db_password>@usserandpassword.ipytker.mongodb.net/?appName=UsserAndPassword';

mongoose.connect(MONGO_URI)
    .then(() => console.log('Conectado exitosamente a MongoDB Atlas'))
    .catch(err => console.error('Error al conectar a MongoDB:', err));

// Definir el Esquema y Modelo de Usuario en la Base de Datos
const userSchema = new mongoose.Schema({
    usuario: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true }
});

const Usuario = mongoose.model('Usuario', userSchema);

app.post('/api/register', async (req, res) => {
    try {
        const { usuario, password } = req.body;
        if (!usuario || !password) {
            return res.status(400).json({ error: 'Faltan campos obligatorios.' });
        }

        const usuarioExiste = await Usuario.findOne({ usuario });
        if (usuarioExiste) {
            return res.status(400).json({ error: 'El nombre de usuario ya está en uso.' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        const nuevoUsuario = new Usuario({ usuario, passwordHash });
        await nuevoUsuario.save();

        res.status(201).json({ message: 'Usuario registrado exitosamente.' });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { usuario, password } = req.body;
        const userRecord = await Usuario.findOne({ usuario });
        
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

// RUTA: Eliminar cuenta de la base de datos
app.delete('/api/delete-account', async (req, res) => {
    try {
        const { usuario } = req.body;
        if (!usuario) {
            return res.status(400).json({ error: 'No se especificó el usuario.' });
        }

        const resultado = await Usuario.findOneAndDelete({ usuario });
        if (!resultado) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        
        res.json({ message: 'Cuenta eliminada permanentemente de la base de datos.' });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
