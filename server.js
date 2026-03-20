require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Configurações de Segurança
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_paroquia_123';

// 1. Conexão Banco de Dados
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Banco de Dados Conectado!'))
  .catch(err => console.error('❌ Erro no banco:', err));

// 2. SCHEMAS

// Schema de Usuário
const userSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  uid: String, // Para GoogleID ou AppleID
  username: { type: String, unique: true, sparse: true }, // Apenas para SuperUser/Admin
  password: { type: String }, // Apenas para SuperUser/Admin
  role: { 
    type: String, 
    enum: ['user', 'superuser', 'admin'], 
    default: 'user' 
  },
  isAtivo: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Schema da Ficha (Atualizado com criadoPor)
const fichaSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  dataNascimento: String,
  cidadeNascimento: String,
  ufNascimento: String,
  nomePai: String,
  celularPai: String,
  foneFixoPai: String,
  nomeMae: String,
  celularMae: String,
  foneFixoMae: String,
  cep: String,
  rua: String,
  numero: String,
  bairro: String,
  paroquiaAtual: String,
  catequistaAtual: String,
  paisCasados: String,
  paroquiaCasamento: String,
  isBatizado: String,
  dataBatismo: String,
  paroquiaBatismo: String,
  cidadeBatismo: String,
  ufBatismo: String,
  assinaturaBase64: String,
  inscricaoBatismo: { type: Boolean, default: false },
  inscricaoEucaristia: { type: Boolean, default: false },
  inscricaoCrisma: { type: Boolean, default: false },
  inscricaoPreCatequese: { type: Boolean, default: false },
  etapa: String,
  status: { 
    type: String, 
    enum: ['ativo', 'pendente', 'arquivado', 'arquivado concluído'], 
    default: 'pendente' // Padrão agora é pendente para novos cadastros
  },
  isAtivo: { type: Boolean, default: true },
  criadoPor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Link com quem criou
}, { timestamps: true });

const Ficha = mongoose.model('Ficha', fichaSchema);

// 3. MIDDLEWARE DE AUTENTICAÇÃO
const autenticar = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ erro: 'Acesso negado. Faça login.' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user || !req.user.isAtivo) throw new Error();
    next();
  } catch (e) {
    res.status(401).json({ erro: 'Token inválido ou usuário inativo.' });
  }
};

// 4. ROTAS DE AUTENTICAÇÃO

// Login/Cadastro via Google ou Apple (Destinado a 'user')
app.post('/api/auth/external', async (req, res) => {
  const { nome, email, uid } = req.body;
  try {
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ nome, email, uid, role: 'user' });
      await user.save();
    }
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, user });
  } catch (e) {
    res.status(500).json({ erro: 'Erro no login externo' });
  }
});

// Login via Usuário/Senha (Destinado a 'superuser' e 'admin')
app.post('/api/auth/internal', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ erro: 'Usuário ou senha incorretos' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, user });
  } catch (e) {
    res.status(500).json({ erro: 'Erro no login interno' });
  }
});

// 5. ROTAS DE FICHAS (COM PROTEÇÃO)

app.post('/api/fichas', autenticar, async (req, res) => {
  try {
    // Regra: 'user' comum só pode criar 1 ficha
    if (req.user.role === 'user') {
      const count = await Ficha.countDocuments({ criadoPor: req.user._id });
      if (count >= 1) return res.status(403).json({ erro: 'Limite de 1 ficha atingido por usuário.' });
      req.body.status = 'pendente'; // Força pendente para usuários comuns
    }

    const novaFicha = new Ficha({ ...req.body, criadoPor: req.user._id });
    await novaFicha.save();
    res.status(201).json(novaFicha);
  } catch (erro) {
    res.status(500).json({ erro: 'Erro ao salvar ficha' });
  }
});

app.get('/api/fichas', autenticar, async (req, res) => {
  try {
    let filtro = { isAtivo: true };
    
    // Regra de Visibilidade:
    // User só vê a própria. Admin/SuperUser vêm todas as ativas.
    if (req.user.role === 'user') {
      filtro.criadoPor = req.user._id;
    }

    // Admin pode querer ver as inativas (opcional via query string)
    if (req.user.role === 'admin' && req.query.incluirInativos === 'true') {
      delete filtro.isAtivo;
    }

    const fichas = await Ficha.find(filtro).sort({ nome: 1 });
    res.status(200).json(fichas);
  } catch (erro) {
    res.status(500).json({ erro: 'Erro ao buscar fichas' });
  }
});

app.put('/api/fichas/:id', autenticar, async (req, res) => {
  try {
    // Busca a ficha primeiro para verificar propriedade
    const ficha = await Ficha.findById(req.params.id);
    if (!ficha) return res.status(404).json({ erro: 'Ficha não encontrada' });

    // Regra: User só edita a própria e não pode mudar o Status nem Inscrição (tratado no Flutter)
    if (req.user.role === 'user' && ficha.criadoPor.toString() !== req.user._id.toString()) {
      return res.status(403).json({ erro: 'Você não tem permissão para editar esta ficha' });
    }

    const atualizada = await Ficha.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(atualizada);
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao atualizar' });
  }
});

// 6. ROTAS DE ADMINISTRAÇÃO (CRUD DE USUÁRIOS)

app.get('/api/admin/users', autenticar, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso restrito' });
  const users = await User.find().sort({ nome: 1 });
  res.json(users);
});

app.post('/api/admin/users', autenticar, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso restrito' });
  try {
    const { password, ...dados } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const novoUser = new User({ ...dados, password: hashedPassword });
    await novoUser.save();
    res.status(201).json(novoUser);
  } catch (e) {
    res.status(400).json({ erro: 'Erro ao criar usuário interno' });
  }
});

// 7. INICIALIZAÇÃO
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));