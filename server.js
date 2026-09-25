const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');

// NOTA: Asegúrate de instalar stripe ejecutando: npm install stripe
// y configurar tu Stripe Secret Key en las variables de entorno (process.env.STRIPE_SECRET_KEY)
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY || 'sk_test_tu_clave_de_prueba');

const app = express();

app.use(express.json());
app.use(cors());

// CONEXIÓN A MONGODB ATLAS
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://luigiguilamo_db_user:Password123@usserandpassword.ipytker.mongodb.net/?appName=UsserAndPassword';

mongoose.connect(MONGO_URI)
    .then(() => console.log('Conectado exitosamente a MongoDB Atlas'))
    .catch(err => console.error('Error al conectar a MongoDB:', err));

// Esquema y Modelo de Usuario actualizado con los campos de Planes y Suscripción
const userSchema = new mongoose.Schema({
    usuario: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    role: { type: String, default: 'user' }, // 'admin' o 'user'
    is_lifetime_premium: { type: Boolean, default: false },
    subscription_status: { type: String, default: 'inactive' }, // 'active' o 'inactive'
    stripe_customer_id: { type: String, default: '' },
    descargas_permitidas_mes: { type: Number, default: 0 },
    descargas_realizadas_mes: { type: Number, default: 0 },
    subscription_end_date: { type: Date, default: null }
});

const Usuario = mongoose.model('Usuario', userSchema);

// RUTA: Registro de Usuario (con verificación automática para LguilamoS)
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

        // Definir privilegios si es la cuenta maestra de LguilamoS
        let role = 'user';
        let is_lifetime_premium = false;
        let descargas_permitidas_mes = 0;
        let subscription_status = 'inactive';

        if (usuario === 'LguilamoS') {
            role = 'admin';
            is_lifetime_premium = true;
            descargas_permitidas_mes = 999999; // Ilimitado
            subscription_status = 'active';
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        const nuevoUsuario = new Usuario({
            usuario,
            passwordHash,
            role,
            is_lifetime_premium,
            subscription_status,
            descargas_permitidas_mes,
            descargas_realizadas_mes: 0
        });

        await nuevoUsuario.save();

        res.status(201).json({ message: 'Usuario registrado exitosamente.' });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// RUTA: Inicio de sesión (refuerza los privilegios VIP de LguilamoS)
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

        // Forzar privilegios VIP si el usuario es LguilamoS al iniciar sesión
        if (usuario === 'LguilamoS') {
            userRecord.role = 'admin';
            userRecord.is_lifetime_premium = true;
            userRecord.descargas_permitidas_mes = 999999;
            userRecord.subscription_status = 'active';
            await userRecord.save();
        }

        res.json({ 
            message: 'Inicio de sesión exitoso', 
            usuario: userRecord.usuario,
            userId: userRecord._id 
        });
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// RUTA: Consultar estado de suscripción del usuario por su ID
app.get('/api/usuario/:id', async (req, res) => {
    try {
        const user = await Usuario.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Error interno del servidor.' });
    }
});

// RUTA: Crear sesión de pago en Stripe para los 3 planes (Estándar, Pro, Premium)
app.post('/api/crear-sesion-pago', async (req, res) => {
    try {
        const { userId, tipoPlan } = req.body; // 'estandar', 'pro', 'premium'

        let priceId = '';
        if (tipoPlan === 'estandar') {
            priceId = process.env.STRIPE_PRICE_ID_ESTANDAR || 'price_1StandarIDDePrueba';
        } else if (tipoPlan === 'pro') {
            priceId = process.env.STRIPE_PRICE_ID_PRO || 'price_1ProIDDePrueba';
        } else if (tipoPlan === 'premium') {
            priceId = process.env.STRIPE_PRICE_ID_PREMIUM || 'price_1PremiumIDDePrueba';
        } else {
            return res.status(400).json({ error: 'Plan no válido.' });
        }

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: [{ price: priceId, quantity: 1 }],
            mode: 'subscription',
            success_url: 'https://tu-usuario.github.io/tu-web/exito.html', // Modifica con tu URL final
            cancel_url: 'https://tu-usuario.github.io/tu-web/cancelado.html', // Modifica con tu URL final
            metadata: { userId, tipoPlan }
        });

        res.json({ url: session.url });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// RUTA O WEBHOOK DE STRIPE: Aquí se procesa la activación de límites tras el pago exitoso
app.post('/api/webhook-stripe', express.raw({type: 'application/json'}), async (req, res) => {
    // Nota: Configura tu endpoint de Webhook de Stripe apuntando a esta ruta para producción
    const sig = req.headers['stripe-signature'];
    let event;

    try {
        // En producción valida con tu webhook secret: stripe.webhooks.constructEvent(...)
        event = req.body; 

        if (event.type === 'checkout.session.completed') {
            const session = event.data.object;
            const userId = session.metadata.userId;
            const tipoPlan = session.metadata.tipoPlan;

            if (tipoPlan === 'estandar') {
                await Usuario.findByIdAndUpdate(userId, {
                    subscription_status: 'active',
                    stripe_customer_id: session.customer,
                    descargas_permitidas_mes: 10, // Límite Plan Estándar (Ej: 10 lotes)
                    descargas_realizadas_mes: 0,
                    subscription_end_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
                });
            } else if (tipoPlan === 'pro') {
                await Usuario.findByIdAndUpdate(userId, {
                    subscription_status: 'active',
                    stripe_customer_id: session.customer,
                    descargas_permitidas_mes: 50, // Límite Plan Pro (Ej: 50 lotes)
                    descargas_realizadas_mes: 0,
                    subscription_end_date: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
                });
            } else if (tipoPlan === 'premium') {
                await Usuario.findByIdAndUpdate(userId, {
                    subscription_status: 'active',
                    stripe_customer_id: session.customer,
                    descargas_permitidas_mes: 999999, // Ilimitado por 1 año ($199.99/año)
                    descargas_realizadas_mes: 0,
                    subscription_end_date: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
                });
            }
        }

        res.json({received: true});
    } catch (err) {
        return res.status(400).send(`Webhook Error: ${err.message}`);
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
