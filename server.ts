import express from 'express';
import bcrypt from 'bcryptjs';
import rateLimit from 'express-rate-limit';

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Configuração do Limitador: Máximo de 2 contas por IP a cada 12 horas
const limitadorCadastro = rateLimit({
  windowMs: 12 * 60 * 60 * 1000, // 12 horas em milissegundos (12h * 60m * 60s * 1000ms)
  max: 2, // Máximo de 2 requisições por IP
  message: { 
    mensagem: "Limite de criação de contas atingido para este IP. Tente novamente após 12 horas." 
  }
});

// Aumentando a capacidade do nosso "banco" temporário em memória
const LIMITE_MAXIMO_USUARIOS = 1000;

// Estrutura de dados em memória
interface Tarefa {
  id: number;
  titulo: string;
  comentario: string;
  dataLimite: string;
  importancia: string;
  dificuldade: string;
}

interface DiarioEntry {
  id: number;
  texto: string;
  dataHora: string;
}

interface Usuario {
  user: string;
  passwordHash: string;
  tarefas: Tarefa[];
  diario: DiarioEntry[];
}

import path from 'path';

// Serve os arquivos estáticos da pasta 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Redireciona a raiz '/' direto para o login
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

const bancoUsuarios: Usuario[] = [];

// 1. CADASTRAR USUÁRIO
app.post('/cadastrar', limitadorCadastro, async (req, res) => {
  const { user, password } = req.body;

  if (!user || !password) {
    return res.status(400).json({ mensagem: "Usuário e senha são obrigatórios." });
  }

  const usuarioExistente = bancoUsuarios.find(u => u.user === user);
  if (usuarioExistente) {
    return res.status(400).json({ mensagem: "Usuário já existe!" });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  
  bancoUsuarios.push({
    user,
    passwordHash,
    tarefas: [],
    diario: []
  });

  return res.status(201).json({ mensagem: "Conta criada com sucesso!" });
});

// 2. LOGIN
app.post('/login', async (req, res) => {
  try {
    const { user, password } = req.body;

    if (!user || !password) {
      return res.status(400).json({ mensagem: "Usuário e senha são obrigatórios." });
    }

    const usuario = bancoUsuarios.find(u => u.user === user);
    if (!usuario) {
      return res.status(401).json({ mensagem: "Usuário ou senha incorretos." });
    }

    const senhaValida = await bcrypt.compare(password, usuario.passwordHash);
    if (!senhaValida) {
      return res.status(401).json({ mensagem: "Usuário ou senha incorretos." });
    }

    return res.status(200).json({ mensagem: "Login efetuado com sucesso!", user: usuario.user });
  } catch (error) {
    console.error("Erro no login:", error);
    return res.status(500).json({ mensagem: "Erro interno no servidor." });
  }
});

// 3. BUSCAR DADOS DO USUÁRIO (Tarefas e Diário)
app.get('/api/dados/:user', (req, res) => {
  const { user } = req.params;
  const usuario = bancoUsuarios.find(u => u.user === user);

  if (!usuario) {
    return res.status(404).json({ mensagem: "Usuário não encontrado." });
  }

  return res.json({ tarefas: usuario.tarefas, diario: usuario.diario });
});

// 4. ADICIONAR TAREFA
app.post('/api/tarefas', (req, res) => {
  const { user, tarefa } = req.body;
  const usuario = bancoUsuarios.find(u => u.user === user);

  if (!usuario) return res.status(404).json({ mensagem: "Usuário não encontrado." });

  usuario.tarefas.push(tarefa);
  return res.status(201).json({ mensagem: "Tarefa salva com sucesso!" });
});

// 5. DELETAR TAREFA
app.delete('/api/tarefas', (req, res) => {
  const { user, id } = req.body;
  const usuario = bancoUsuarios.find(u => u.user === user);

  if (!usuario) return res.status(404).json({ mensagem: "Usuário não encontrado." });

  usuario.tarefas = usuario.tarefas.filter(t => t.id !== id);
  return res.json({ mensagem: "Tarefa removida com sucesso!" });
});

// 6. ADICIONAR REGISTRO AO DIÁRIO
app.post('/api/diario', (req, res) => {
  const { user, registro } = req.body;
  const usuario = bancoUsuarios.find(u => u.user === user);

  if (!usuario) return res.status(404).json({ mensagem: "Usuário não encontrado." });

  usuario.diario.unshift(registro);
  return res.status(201).json({ mensagem: "Registro salvo no diário!" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
}); 