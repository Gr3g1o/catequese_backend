require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' })); // Essencial para receber a assinatura em imagem

// 1. Conexão Segura
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Banco de Dados Conectado!'))
  .catch(err => console.error('❌ Erro no banco:', err));

// 2. O Molde da Ficha (Schema completo)
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
  isAtivo: { type: Boolean, default: true },
  usuarioId: String // Preparado para o sistema de Login futuro
}, { timestamps: true });

const Ficha = mongoose.model('Ficha', fichaSchema);

// 3. Rotas da API
app.post('/api/fichas', async (req, res) => {
  try {
    const novaFicha = new Ficha(req.body);
    await novaFicha.save();
    res.status(201).json({ mensagem: 'Ficha salva!', ficha: novaFicha });
  } catch (erro) {
    res.status(500).json({ erro: 'Falha ao salvar a ficha', detalhes: erro.message });
  }
});

app.get('/api/fichas', async (req, res) => {
  try {
    const fichas = await Ficha.find({ isAtivo: true }).sort({ createdAt: -1 });
    res.status(200).json(fichas);
  } catch (erro) {
    res.status(500).json({ erro: 'Falha ao buscar fichas' });
  }
});

app.put('/api/fichas/:id', async (req, res) => {
  try {
    const fichaAtualizada = await Ficha.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.status(200).json(fichaAtualizada);
  } catch (erro) {
    res.status(500).json({ erro: 'Erro ao atualizar a ficha' });
  }
});

// Rota para INATIVAR (Soft Delete) uma ficha (PATCH)
app.patch('/api/fichas/:id/inativar', async (req, res) => {
  try {
    await Ficha.findByIdAndUpdate(req.params.id, { isAtivo: false });
    res.status(200).json({ mensagem: 'Ficha inativada com sucesso' });
  } catch (erro) {
    res.status(500).json({ erro: 'Erro ao inativar a ficha' });
  }
});

// 4. Inicialização
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});