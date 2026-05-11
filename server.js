// server.js - VERSIÓN CORREGIDA Y COMPLETA
require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER || 'localhost',
    database: process.env.DB_DATABASE || 'CinetecaDB',
    options: {
        encrypt: false,
        trustServerCertificate: true,
        enableArithAbort: true
    }
};

let pool;

async function initDB() {
    try {
        pool = await sql.connect(dbConfig);
        console.log('✅ Conectado a SQL Server');

        // Tabla Usuarios
        await pool.request().query(`
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Usuarios' AND xtype='U')
            CREATE TABLE Usuarios (
                id INT IDENTITY(1,1) PRIMARY KEY,
                nombre NVARCHAR(100),
                email NVARCHAR(150) UNIQUE NOT NULL,
                password NVARCHAR(255) NOT NULL,
                rol NVARCHAR(20) NOT NULL DEFAULT 'consultor'
            )
        `);

        // Tabla Peliculas
        await pool.request().query(`
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Peliculas' AND xtype='U')
            CREATE TABLE Peliculas (
                id INT IDENTITY(1,1) PRIMARY KEY,
                Titulo NVARCHAR(200) NOT NULL,
                Año INT,
                Genero NVARCHAR(100),
                Duracion INT,
                Pais NVARCHAR(100) DEFAULT 'Desconocido',
                Director NVARCHAR(150),
                Sinopsis NVARCHAR(MAX)
            )
        `);

        // Tabla Salas
        await pool.request().query(`
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Salas' AND xtype='U')
            CREATE TABLE Salas (
                id INT IDENTITY(1,1) PRIMARY KEY,
                nombre NVARCHAR(100) NOT NULL,
                capacidad INT NOT NULL,
                tecnologia NVARCHAR(200)
            )
        `);

        // Tabla Funciones
        await pool.request().query(`
            IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Funciones' AND xtype='U')
            CREATE TABLE Funciones (
                id INT IDENTITY(1,1) PRIMARY KEY,
                peliculaId INT NOT NULL,
                salaId INT NOT NULL,
                fecha DATE NOT NULL,
                hora TIME NOT NULL,
                precio DECIMAL(10, 2) NOT NULL DEFAULT 15.00,
                asientosDisponibles INT NOT NULL DEFAULT 100,
                FOREIGN KEY (peliculaId) REFERENCES Peliculas(id) ON DELETE CASCADE,
                FOREIGN KEY (salaId) REFERENCES Salas(id) ON DELETE CASCADE
            )
        `);

        console.log('✅ Tablas listas');
    } catch (err) {
        console.error('❌ Error DB:', err.message);
    }
}

// ====================== AUTH ======================
app.post('/api/auth/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    try {
        const hashed = await bcrypt.hash(password, 10);
        await pool.request()
            .input('nombre', sql.NVarChar, nombre)
            .input('email', sql.NVarChar, email)
            .input('password', sql.NVarChar, hashed)
            .query(`INSERT INTO Usuarios (nombre, email, password, rol) VALUES (@nombre, @email, @password, 'consultor')`);
        res.status(201).json({ message: 'Usuario registrado correctamente' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.request()
            .input('email', sql.NVarChar, email)
            .query('SELECT * FROM Usuarios WHERE email = @email');

        const user = result.recordset[0];
        if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

        const token = jwt.sign(
            { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol },
            process.env.JWT_SECRET || 'secret_key',
            { expiresIn: '8h' }
        );

        res.json({ 
            token, 
            usuario: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol } 
        });
    } catch (err) {
        console.error('Error en login:', err);
        res.status(500).json({ error: 'Error del servidor' });
    }
});

// ====================== USUARIOS ======================
app.get('/api/usuarios', async (req, res) => {
    try {
        const result = await pool.request().query('SELECT id, nombre, email, rol FROM Usuarios ORDER BY id DESC');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/usuarios', async (req, res) => {
    const { nombre, email, password, rol } = req.body;
    try {
        const hashed = await bcrypt.hash(password, 10);
        const result = await pool.request()
            .input('nombre', sql.NVarChar, nombre)
            .input('email', sql.NVarChar, email)
            .input('password', sql.NVarChar, hashed)
            .input('rol', sql.NVarChar, rol || 'consultor')
            .query(`INSERT INTO Usuarios (nombre, email, password, rol) OUTPUT INSERTED.id, INSERTED.nombre, INSERTED.email, INSERTED.rol VALUES (@nombre, @email, @password, @rol)`);
        res.status(201).json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/usuarios/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.request()
            .input('id', sql.Int, id)
            .query('DELETE FROM Usuarios WHERE id = @id');
        res.json({ message: 'Usuario eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/usuarios/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre, email, rol } = req.body;
    try {
        await pool.request()
            .input('id', sql.Int, id)
            .input('nombre', sql.NVarChar, nombre)
            .input('email', sql.NVarChar, email)
            .input('rol', sql.NVarChar, rol)
            .query(`UPDATE Usuarios SET nombre = @nombre, email = @email, rol = @rol WHERE id = @id`);
        
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT id, nombre, email, rol FROM Usuarios WHERE id = @id');
        
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ====================== PELÍCULAS ======================
app.get('/api/peliculas', async (req, res) => {
    try {
        const result = await pool.request().query('SELECT * FROM Peliculas ORDER BY id DESC');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/peliculas', async (req, res) => {
    const { Titulo, Año, Genero, Duracion } = req.body;
    try {
        const result = await pool.request()
            .input('Titulo', sql.NVarChar, Titulo)
            .input('Año', sql.Int, Año)
            .input('Genero', sql.NVarChar, Genero)
            .input('Duracion', sql.Int, Duracion)
            .query(`
                INSERT INTO Peliculas (Titulo, Año, Genero, Duracion, Pais, Director, Sinopsis)
                OUTPUT INSERTED.*
                VALUES (@Titulo, @Año, @Genero, @Duracion, 'Desconocido', '', '')
            `);
        res.status(201).json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/peliculas/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.request()
            .input('id', sql.Int, id)
            .query('DELETE FROM Peliculas WHERE id = @id');
        res.json({ message: 'Película eliminada' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/peliculas/:id', async (req, res) => {
    const { id } = req.params;
    const { Titulo, Año, Genero, Duracion } = req.body;
    try {
        await pool.request()
            .input('id', sql.Int, id)
            .input('Titulo', sql.NVarChar, Titulo)
            .input('Año', sql.Int, Año)
            .input('Genero', sql.NVarChar, Genero)
            .input('Duracion', sql.Int, Duracion)
            .query(`UPDATE Peliculas SET Titulo = @Titulo, Año = @Año, Genero = @Genero, Duracion = @Duracion WHERE id = @id`);
        
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT * FROM Peliculas WHERE id = @id');
        
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ====================== SALAS ======================
app.get('/api/salas', async (req, res) => {
    try {
        const result = await pool.request().query('SELECT * FROM Salas ORDER BY id DESC');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/salas', async (req, res) => {
    const { nombre, capacidad, tecnologia } = req.body;
    try {
        const result = await pool.request()
            .input('nombre', sql.NVarChar, nombre)
            .input('capacidad', sql.Int, capacidad)
            .input('tecnologia', sql.NVarChar, tecnologia)
            .query(`
                INSERT INTO Salas (nombre, capacidad, tecnologia)
                OUTPUT INSERTED.*
                VALUES (@nombre, @capacidad, @tecnologia)
            `);
        res.status(201).json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/salas/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.request()
            .input('id', sql.Int, id)
            .query('DELETE FROM Salas WHERE id = @id');
        res.json({ message: 'Sala eliminada' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/salas/:id', async (req, res) => {
    const { id } = req.params;
    const { nombre, capacidad, tecnologia } = req.body;
    try {
        await pool.request()
            .input('id', sql.Int, id)
            .input('nombre', sql.NVarChar, nombre)
            .input('capacidad', sql.Int, capacidad)
            .input('tecnologia', sql.NVarChar, tecnologia)
            .query(`UPDATE Salas SET nombre = @nombre, capacidad = @capacidad, tecnologia = @tecnologia WHERE id = @id`);
        
        const result = await pool.request()
            .input('id', sql.Int, id)
            .query('SELECT * FROM Salas WHERE id = @id');
        
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ====================== FUNCIONES ======================
app.get('/api/funciones', async (req, res) => {
    try {
        const result = await pool.request().query(`
            SELECT 
                f.id,
                f.peliculaId,
                f.salaId,
                CONVERT(VARCHAR(10), f.fecha, 23) as fecha,
                CONVERT(VARCHAR(8), f.hora, 108) as hora,
                f.precio,
                f.asientosDisponibles,
                p.Titulo as peliculaTitulo,
                s.nombre as salaNombre
            FROM Funciones f
            LEFT JOIN Peliculas p ON f.peliculaId = p.id
            LEFT JOIN Salas s ON f.salaId = s.id
            ORDER BY f.fecha DESC, f.hora DESC
        `);
        res.json(result.recordset);
    } catch (err) {
        console.error('Error en GET funciones:', err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/funciones', async (req, res) => {
    const { peliculaId, salaId, fecha, hora, precio } = req.body;
    
    if (!peliculaId || !salaId || !fecha || !hora || !precio) {
        return res.status(400).json({ error: 'Faltan parámetros requeridos' });
    }

    try {
        // ✅ CONVERTIR HORA CORRECTAMENTE A FORMATO HH:mm:ss
        let horaFormato = hora;
        
        if (typeof hora === 'string') {
            // Si viene en formato HH:mm, agregar :00
            if (hora.length === 5 && hora.match(/^\d{2}:\d{2}$/)) {
                horaFormato = `${hora}:00`;
            }
        }

        // ✅ VALIDAR FORMATO FINAL
        if (!/^\d{2}:\d{2}:\d{2}$/.test(horaFormato)) {
            console.error('❌ Formato de hora inválido:', horaFormato);
            return res.status(400).json({ error: 'Formato de hora inválido. Debe ser HH:mm:ss' });
        }

        // ✅ CONVERTIR FECHA CORRECTAMENTE
        const fechaObj = new Date(fecha);
        if (isNaN(fechaObj.getTime())) {
            return res.status(400).json({ error: 'Formato de fecha inválido' });
        }

        console.log('✅ Datos a insertar:');
        console.log('  - Película ID:', peliculaId);
        console.log('  - Sala ID:', salaId);
        console.log('  - Fecha:', fechaObj.toISOString().split('T')[0]);
        console.log('  - Hora:', horaFormato);
        console.log('  - Precio:', precio);

        // ✅ USAR CAST EN LA CONSULTA PARA CONVERTIR A TIME
        const result = await pool.request()
            .input('peliculaId', sql.Int, parseInt(peliculaId))
            .input('salaId', sql.Int, parseInt(salaId))
            .input('fecha', sql.Date, fechaObj)
            .input('hora', sql.VarChar, horaFormato) // ✅ Pasar como VarChar
            .input('precio', sql.Decimal(10, 2), parseFloat(precio))
            .query(`
                INSERT INTO Funciones (peliculaId, salaId, fecha, hora, precio, asientosDisponibles)
                OUTPUT INSERTED.*
                VALUES (@peliculaId, @salaId, @fecha, CAST(@hora AS TIME), @precio, 100)
            `);
        
        res.status(201).json(result.recordset[0]);
        console.log('✅ Función creada correctamente');
        
    } catch (err) {
        console.error('❌ Error en POST funciones:', err.message);
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/funciones/:id', async (req, res) => {
    const { id } = req.params;
    try {
        await pool.request()
            .input('id', sql.Int, id)
            .query('DELETE FROM Funciones WHERE id = @id');
        res.json({ message: 'Función eliminada' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/funciones/:id', async (req, res) => {
    const { id } = req.params;
    const { fecha, hora, precio } = req.body;
    
    try {
        // ✅ VALIDAR Y CONVERTIR HORA
        let horaFormato = hora;
        if (typeof hora === 'string' && hora.length === 5 && hora.match(/^\d{2}:\d{2}$/)) {
            horaFormato = `${hora}:00`;
        }

        if (!/^\d{2}:\d{2}:\d{2}$/.test(horaFormato)) {
            return res.status(400).json({ error: 'Formato de hora inválido' });
        }

        const fechaObj = new Date(fecha);
        if (isNaN(fechaObj.getTime())) {
            return res.status(400).json({ error: 'Formato de fecha inválido' });
        }

        await pool.request()
            .input('id', sql.Int, parseInt(id))
            .input('fecha', sql.Date, fechaObj)
            .input('hora', sql.VarChar, horaFormato)
            .input('precio', sql.Decimal(10, 2), parseFloat(precio))
            .query(`UPDATE Funciones SET fecha = @fecha, hora = CAST(@hora AS TIME), precio = @precio WHERE id = @id`);
        
        const result = await pool.request()
            .input('id', sql.Int, parseInt(id))
            .query('SELECT * FROM Funciones WHERE id = @id');
        
        res.json(result.recordset[0]);
        
    } catch (err) {
        console.error('❌ Error en PUT funciones:', err.message);
        res.status(500).json({ error: err.message });
    }
});
// ====================== INICIAR SERVIDOR ======================
app.listen(PORT, async () => {
    console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
    await initDB();
});