# Sistema de Agendamentos

Sistema de gestão de agendamentos por horário para múltiplas unidades.

## Como rodar

### 1. Instalar dependências
```bash
pip install flask
```

### 2. Iniciar o sistema
```bash
python app.py
```

### 3. Acessar no navegador
```
http://localhost:5000
```

## Funcionalidades

- **Dashboard** — Resumo geral com filtro por dia ou mês, ranking por unidade e ranking de líderes
- **Unidades** — Agendamentos por horário (08H–18H) com auto-save, exportação CSV, resumo do dia e registro de comparecimentos
- **Funcionários** — Cadastro e gerenciamento de funcionários por unidade

## Unidades
PARÁ, MANAUS, MANOA, SÃO LUIZ, FORTALEZA, AÇÃO

## Estrutura
```
sistema_agendamentos/
├── app.py              # Servidor Flask + rotas
├── database.py         # Banco de dados SQLite
├── requirements.txt    # Dependências
├── agendamentos.db     # Banco de dados (criado automaticamente)
├── templates/
│   ├── base.html       # Layout base com sidebar
│   ├── dashboard.html  # Tela principal
│   ├── unit.html       # Agendamentos por unidade
│   └── employees.html  # Funcionários
└── static/
    └── style.css       # Tema escuro dourado
```
