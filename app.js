const Lock = require('async-lock'); // Se utiliza un sistema de locking
const lock = new Lock();


let tempOmadaParams = {};  // Variable para almacenar temporalmente los parámetros de Omada


require('dotenv').config();
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const path = require('path');
const { google } = require('googleapis');
const sheets = google.sheets('v4');
const fs = require('fs');
const compression = require('compression');  // Agregado para compresión de respuestas
const FileStore = require('session-file-store')(session);


// Inicializar la app de express
const app = express();


// Middleware
app.use(compression());  // Compresión de respuestas para mejorar la velocidad de carga
app.use(express.static('public'));
app.use(express.json());  // Para manejar cuerpos JSON
app.use(express.urlencoded({ extended: true })); // Para manejar el envío de formularios


// Configuración de sesiones con almacenamiento en archivos temporales y eliminación automática en 24 horas
app.use(session({
  store: new FileStore({
    path: './sessions',
    ttl: 24 * 3600  // Tiempo de vida de la sesión en segundos (24 horas)
  }),
  secret: 'your-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,  // Evita el acceso a las cookies desde JavaScript
    maxAge: 24 * 3600 * 1000
  }
}));


app.use(passport.initialize());
app.use(passport.session());


// Configuración de estrategia de Google OAuth
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.REDIRECT_URI
}, (accessToken, refreshToken, profile, done) => {
  return done(null, profile);
}));


// Serialización del usuario en la sesión
passport.serializeUser((user, done) => {
  done(null, user);
});


// Deserialización del usuario desde la sesión
passport.deserializeUser((user, done) => {
  done(null, user);
});


function isValidMAC(mac) {
  return /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/.test(mac);
}


function isValidIP(ip) {
  return /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip);
}


app.get('/login', (req, res, next) => {
  try {
    const { client_mac, client_ip, ap_mac, ssid, redirect } = req.query;


    if (!client_mac || !client_ip || !ap_mac || !ssid || !redirect) {
      return res.status(400).send('Error: Parámetros de Omada faltantes o inválidos.');
    }


    // Validar formato de los parámetros MAC e IP
    if (!isValidMAC(client_mac) || !isValidMAC(ap_mac) || !isValidIP(client_ip)) {
      return res.status(400).send('Error: Formato de MAC o IP inválido.');
    }


    console.log("Parámetros recibidos de Omada", { client_mac, client_ip, ap_mac, ssid, redirect });


    tempOmadaParams = { client_mac, client_ip, ap_mac, ssid, redirect };
    req.session.omadaParams = tempOmadaParams;


    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  } catch (error) {
    next(error);
  }
});


// Ruta para iniciar la autenticación con Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));


app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  async (req, res) => {
    try {
      if (!tempOmadaParams) throw new Error('Parámetros de Omada faltantes o sesión expirada.');


      req.session.omadaParams = tempOmadaParams;
      await req.session.save();


      // Validar si los datos de Google son correctos
      if (!req.user || !req.user.emails || !req.user.emails[0].value) {
        throw new Error('Error al autenticar con Google. Faltan datos de usuario.');
      }


      await lock.acquire('addToSheet', async () => {
        await addToSheet(req.user, req.session.omadaParams);
      });


      res.redirect('/success');
    } catch (err) {
      console.error('Error durante la autenticación de Google o el guardado de sesión:', err);
      res.status(500).send('Error al ingresar al Wi-Fi. Por favor, inténtalo nuevamente.');
    }
  }
);


app.post('/auth/manual', (req, res) => {
  const { name, email } = req.body;


  if (!name || !email) {
    return res.status(400).send('Error: Nombre y correo son obligatorios.');
  }


  req.session.user = { displayName: name, email: email };


  req.session.save(async (err) => {
    if (err) {
      console.error('Error al guardar la sesión', err);
      return res.status(500).send('Error al ingresar al Wi-Fi.');
    }


    try {
      await lock.acquire('addToSheet', async () => {
        await addToSheet(req.session.user, req.session.omadaParams);
      });


      res.redirect('/success');
    } catch (error) {
      console.error('Error al enviar los datos a Google Sheets', error);
      return res.status(500).send('Error al ingresar al Wi-Fi.');
    }
  });
});


// Ruta de éxito después de la autenticación
app.get('/success', (req, res) => {
  if (!req.isAuthenticated() && !req.session.user) {
    return res.redirect('/');
  }


  const omadaParams = req.session.omadaParams || {};
  const { client_mac, client_ip, ap_mac, ssid } = omadaParams;


  if (!client_mac || !client_ip || !ap_mac) {
    return res.send('Error: Parámetros de Omada faltantes.');
  }


  const omadaControllerIp = process.env.OMADA_CONTROLLER_IP;
  const omadaUrl = `https://${omadaControllerIp}/login?client_mac=${client_mac}&client_ip=${client_ip}&ap_mac=${ap_mac}&ssid=${ssid}&access=allow`;


  // Verifica si el usuario es de Google o manual
  const userName = req.user ? req.user.displayName : req.session.user.displayName;


  res.send(`
    <!DOCTYPE html>
    <html lang="es">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>¡Disfruta tu WiFi!</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          background-color: #e0f7fa;
        }
        .container {
          text-align: center;
          padding: 30px;
          background-color: white;
          box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
          border-radius: 8px;
          width: 90%;
          max-width: 400px;
        }
        h1 {
          color: #333;
          font-size: 24px;
        }
        p {
          font-size: 18px;
          color: #555;
        }
        .success-icon {
          font-size: 50px;
          color: #66bb6a;
          margin-bottom: 20px;
        }


        @media (max-width: 480px) {
          h1 {
            font-size: 20px;
          }
          p {
            font-size: 16px;
          }
          .container {
            padding: 20px;
          }
          .success-icon {
            font-size: 40px;
          }
        }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="success-icon">✔️</div>
        <h1>¡Conexión exitosa!</h1>
        <p><strong>Bienvenido al Consultorio del Dr. Andersson</strong>. Ya puedes usar el Wi-Fi libremente, <strong>${userName || ''}</strong>.</p>
      </div>
      <script>
      setTimeout(() => {
        try {
          window.location.href = '${omadaUrl}';
        } catch (error) {
          console.error('Error en la redirección:', error);
          alert('Hubo un problema al redirigirte al Wi-Fi. Por favor, intenta nuevamente.');
        }
      }, 3000);
      </script>
    </body>
    </html>
  `);
});


// Middleware de manejo global de errores
app.use((err, req, res, next) => {
  console.error('Error capturado:', err);
  res.status(500).send('Error al ingresar al Wi-Fi.');
});


// Iniciar el servidor en el puerto 3000
app.listen(3000, () => {
  console.log('Servidor ejecutándose en http://localhost:3000');
});


// Autenticación y manejo de la API de Google Sheets
const CREDENTIALS_PATH = path.join(__dirname, 'credentials.json');
let authClient;


function authenticate() {
  const credentials = JSON.parse(fs.readFileSync(CREDENTIALS_PATH));


  authClient = new google.auth.JWT(
    credentials.client_email,
    null,
    credentials.private_key,
    ['https://www.googleapis.com/auth/spreadsheets']
  );


  authClient.authorize((err) => {
    if (err) {
      console.error('Error en la autenticación con la cuenta de servicio', err);
    } else {
      console.log('Autenticación exitosa con la cuenta de servicio');
    }
  });
}


// Función para agregar una nueva fila a Google Sheets con reintentos automáticos
async function addToSheet(googleData, omadaData, retries = 3) {
  try {
    if (!omadaData) {
      console.error('Datos faltantes para Omada');
      throw new Error('Error al enviar datos a Google Sheets.');
    }


    const sheetId = '1rEQgD332zACUo4J5wuCnkweQDEXSl0acGSEL3Zamk5g';
    const values = [
      [
        new Date().toLocaleString(),
        googleData?.displayName || googleData?.name || 'Información no disponible',
        googleData?.emails ? googleData.emails[0].value : googleData?.email || 'Información no disponible',
        googleData?.gender || 'Información no disponible',
        googleData?.ageRange?.min || 'Información no disponible',
        omadaData.client_mac || 'Información no disponible',
        omadaData.client_ip || 'Información no disponible',
        omadaData.ap_mac || 'Información no disponible',
        omadaData.ssid || 'Información no disponible'
      ]
    ];


    const resource = { values };


    await sheets.spreadsheets.values.append({
      auth: authClient,
      spreadsheetId: sheetId,
      range: 'Sheet1!A:I',
      valueInputOption: 'RAW',
      resource,
    });


    console.log('Datos enviados correctamente a Google Sheets');
  } catch (error) {
    if (retries > 0) {
      console.log(`Reintentando... Quedan ${retries} intentos.`);
      await addToSheet(googleData, omadaData, retries - 1);
    } else {
      console.error('Error persistente. No se pudo enviar los datos a Google Sheets', error);
      throw error;  // Propaga el error al middleware global
    }
  }
}


// Llamar a authenticate al iniciar la app
authenticate();



