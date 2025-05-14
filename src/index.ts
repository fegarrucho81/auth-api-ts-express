import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();
const app = express();
const PORT = 3000;

app.use(express.json());

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user:process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database:process.env.DB_NAME
});

db.connect((err) => {
    if (err)
        console.log('Erro ao conectar com banco de dados', err);
    else
        console.log('Conectado ao banco de dados!');
})

// Cadastro
app.post('/register', async (req: Request, res: Response) => {
    const { nome, email, senha } = req.body;
    const hash = await bcrypt.hash(senha, 19);

    db.query(
        'INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
        [nome, email, hash],
        (err, result: any) => {
            if (err)
                return res.status(500).json({ message: 'Erro ao cadastrar.' });
            res.status(201).json({ id: result.insertId, nome, email });
        }
    );
});

// Login
app.post('/login', async (req: Request, res: Response) => {
    const { email, senha } = req.body;

    db.query(
        'SELECT * FROM usuarios WHERE email = ?',
        [email],
        async (err, results: any[]) => {
            if (err || results.length === 0)
                return res.status(401).json({ message: 'Usuário não encontrado.' });

            const usuario = results[0];
            const match = await bcrypt.compare(senha, usuario.senha);
            if (!match) 
                return res.status(401).json({ message: 'Senha incorreta.' });

            const token = jwt.sign({ id: usuario.id, nome: usuario.nome }, process.env.JWT_SECRET as string, {
                expiresIn: '1h'
            });

            res.json({ token });
        }
    );
});

// Middleware de autenticação
function autenticarToken(req: Request, res: Response, next: NextFunction): void {
    const authHeader = req.headers['authorization'];
    const token = authHeader?.split(' ')[1];

    if (!token) {
        res.sendStatus(401);
        return;
    }

    jwt.verify(token, process.env.JWT_SECRET as string, (err, usuario) => {
        if (err) {
            res.sendStatus(403);
            return;
        }

        // Adiciona 'usuario' ao 'req' como uma propriedade dinâmica
        (req as any).usuario = usuario;
        next();
    });
}

// Rota protegida
app.get('/perfil', autenticarToken, (req: Request, res: Response) => {
    // Acessando a propriedade 'usuario' de forma dinâmica
    res.json({ mensagem: 'Perfil acessado!', usuario: (req as any).usuario });
});

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});