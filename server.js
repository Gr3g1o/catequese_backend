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
const JWT_SECRET = process.env.JWT_SECRET || 'chave_secreta_paroquia';

// 1. Conexão Banco de Dados
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Banco de Dados Conectado!'))
  .catch(err => console.error('❌ Erro no banco:', err));

// 2. SCHEMAS
const userSchema = new mongoose.Schema({
  nome: { type: String, default: 'Usuário' },
  email: { type: String, unique: true, required: true },
  otp: { type: String },
  otpExpires: { type: Date },
  username: { type: String, unique: true, sparse: true },
  password: { type: String },
  role: {
    type: String,
    enum: ['user', 'superuser', 'admin'],
    default: 'user'
  },
  isAtivo: { type: Boolean, default: true }
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

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
    default: 'pendente'
  },
  isAtivo: { type: Boolean, default: true },
  criadoPor: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
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
app.post('/api/auth/request-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ erro: 'E-mail é obrigatório' });

  try {
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, role: 'user' }); // Nome padrão será 'Usuário'
    }

    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();
    user.otp = codigoOTP;
    user.otpExpires = Date.now() + 10 * 60 * 1000;
    await user.save();

    const response = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: {
        'accept': 'application/json',
        'api-key': process.env.BREVO_API_KEY,
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        sender: { name: 'App Catequese', email: 'sjocsuporte@gmail.com' },
        to: [{ email: email }],
        subject: 'Seu código de acesso - Catequese',
        htmlContent: `
          <div style="font-family: sans-serif; color: #333;">
            <h2>Olá!</h2>
            <p>Seu código de acesso ao App da Catequese é:</p>
            <h1 style="color: #0D47A1; letter-spacing: 5px;">${codigoOTP}</h1>
            <p>Este código expira em 10 minutos.</p>
            <hr />
            <small>Se você não solicitou este acesso, ignore este e-mail.</small>
          </div>
        `
      })
    });

    if (!response.ok) return res.status(500).json({ erro: 'Falha do Brevo ao enviar e-mail' });
    res.json({ mensagem: 'Código enviado com sucesso!' });

  } catch (e) {
    res.status(500).json({ erro: 'Erro ao processar solicitação de e-mail' });
  }
});

app.post('/api/auth/verify-code', async (req, res) => {
  const { email, code } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user || user.otp !== code || user.otpExpires < Date.now()) {
      return res.status(401).json({ erro: 'Código inválido ou expirado.' });
    }
    user.otp = null;
    user.otpExpires = null;
    await user.save();
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, user });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao validar o código' });
  }
});

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

// 5. ROTAS DO MEU PERFIL (NOVO)
app.get('/api/users/me', autenticar, async (req, res) => {
  res.json(req.user);
});

app.put('/api/users/me', autenticar, async (req, res) => {
  try {
    const { nome, email } = req.body;
    const atualizado = await User.findByIdAndUpdate(
      req.user._id, 
      { nome, email }, 
      { new: true }
    );
    res.json(atualizado);
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao atualizar perfil' });
  }
});

app.patch('/api/users/me/inativar', autenticar, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user._id, { isAtivo: false });
    res.json({ mensagem: 'Conta inativada com sucesso' });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao inativar conta' });
  }
});

// 6. ROTAS DE FICHAS (Com suporte a Paginação)
app.post('/api/fichas', autenticar, async (req, res) => {
  try {
    if (req.user.role === 'user') {
      const count = await Ficha.countDocuments({ criadoPor: req.user._id });
      if (count >= 1) return res.status(403).json({ erro: 'Limite de 1 ficha atingido por usuário.' });
      req.body.status = 'pendente';
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
    if (req.user.role === 'user') filtro.criadoPor = req.user._id;
    if (req.user.role === 'admin' && req.query.incluirInativos === 'true') delete filtro.isAtivo;

    // Configuração de Paginação
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 0; // 0 traz tudo
    const skip = (page - 1) * limit;

    const fichas = await Ficha.find(filtro)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    res.status(200).json(fichas);
  } catch (erro) {
    res.status(500).json({ erro: 'Erro ao buscar fichas' });
  }
});

app.put('/api/fichas/:id', autenticar, async (req, res) => {
  try {
    const ficha = await Ficha.findById(req.params.id);
    if (!ficha) return res.status(404).json({ erro: 'Ficha não encontrada' });
    if (req.user.role === 'user' && ficha.criadoPor.toString() !== req.user._id.toString()) {
      return res.status(403).json({ erro: 'Sem permissão' });
    }
    const atualizada = await Ficha.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json(atualizada);
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao atualizar' });
  }
});

app.patch('/api/fichas/:id/inativar', autenticar, async (req, res) => {
  try {
    if (req.user.role === 'user') return res.status(403).json({ erro: 'Acesso negado' });
    await Ficha.findByIdAndUpdate(req.params.id, { isAtivo: false });
    res.status(200).json({ mensagem: 'Ficha inativada' });
  } catch (erro) {
    res.status(500).json({ erro: 'Erro ao inativar' });
  }
});

// 7. ROTAS DE ADMINISTRAÇÃO (Com suporte a Paginação e Correção de Escopo)
app.get('/api/admin/users', autenticar, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso restrito' });
  
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 0;
  const skip = (page - 1) * limit;

  const users = await User.find()
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit);

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
    res.status(400).json({ erro: 'Erro ao criar usuário' });
  }
});

app.put('/api/admin/users/:id', autenticar, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso restrito' });
  try {
    const { password, ...dados } = req.body;
    if (password && password.trim() !== '') {
      dados.password = await bcrypt.hash(password, 10);
    }
    const atualizado = await User.findByIdAndUpdate(req.params.id, dados, { new: true });
    res.json(atualizado);
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao atualizar usuário' });
  }
});

app.delete('/api/admin/users/:id', autenticar, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso restrito' });
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ mensagem: 'Usuário deletado' });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao deletar usuário' });
  }
});

// 8. INICIALIZAÇÃO
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));

// DELETAR FICHA (Apenas Admin)
app.delete('/api/fichas/:id', autenticar, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ erro: 'Apenas administradores podem deletar fichas permanentemente' });
    }
    const fichaDeletada = await Ficha.findByIdAndDelete(req.params.id);
    if (!fichaDeletada) {
      return res.status(404).json({ erro: 'Ficha não encontrada' });
    }
    res.json({ mensagem: 'Ficha deletada com sucesso' });
  } catch (e) {
    res.status(500).json({ erro: 'Erro ao deletar ficha' });
  }
});
