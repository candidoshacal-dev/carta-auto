import re
import os
import json
import sqlite3
import time
from database import get_connection, init_db

def classify_cat_a(t):
    t = t.lower()
    if any(k in t for k in ['capacete', 'viseira', 'luva', 'bota', 'casaco', 'blusão', 'vestuário', 'cinta abdominal', 'protector', 'protetor', 'óculos', 'calçado', 'roupa', 'fato', 'fecho']):
        return 'Equipamento de Proteção e Segurança do Motociclista'
    elif any(k in t for k in ['travagem', 'travar', 'inclin', 'curva', 'estabilidade', 'queda', 'equilíbrio', 'dinâmica', 'piso', 'aderência', 'chuva', 'vento', 'vento lateral', 'derrap']):
        return 'Dinâmica, Estabilidade e Técnica de Condução'
    elif any(k in t for k in ['álcool', 'tas', 'fadiga', 'cansaço', 'medicamento', 'reação', 'visibilidade', 'visão', 'audição']):
        return 'O Condutor, Fatores Físicos e Segurança Rodoviária'
    elif any(k in t for k in ['carta', 'habilita', 'categoria', 'documento', 'seguro', 'idade', 'inspecção', 'inspeção', 'apreensão', 'coima', 'contra-ordenação', 'contraordenação']):
        return 'Documentação, Habilitação Legal e Sanções'
    else:
        return 'Regras de Trânsito, Circulação e Manobras'

def classify_cat_b(t):
    t = t.lower()
    if any(k in t for k in ['óleo', 'motor', 'pneu', 'pressão', 'amortecedor', 'suspensão', 'bateria', 'radiador', 'líquido de refrigeração', 'vela', 'filtro', 'embraiagem', 'transmissão', 'direcção', 'direção assistida', 'fusível', 'alternador', 'manómetro', 'manometro', 'luz avisadora']):
        return 'Mecânica, Manutenção e Componentes do Veículo'
    elif any(k in t for k in ['álcool', 'alcoolemia', ' tas ', 'tas,', 'tas.', 'bebida', 'droga', 'estupefaciente', 'medicamento', 'fadiga', 'sono', 'sonolência', 'cansaço', 'tempo de reacção', 'tempo de reação', 'distracção', 'distração', 'telemóvel', 'stress', 'visão', 'acuidade']):
        return 'O Condutor: Estado Físico, Psicológico e Fatores de Risco'
    elif any(k in t for k in ['distância de reacção', 'distância de reação', 'distância de travagem', 'distância de segurança', 'distância de paragem', 'limite de velocidade', 'velocidade máxima', 'velocidade mínima', 'excesso de velocidade', 'km/h']):
        return 'Velocidades e Distâncias de Segurança'
    elif any(k in t for k in ['estacionar', 'estacionamento', 'parar', 'paragem de veículos', 'imobilização', 'parque de estacionamento']):
        return 'Paragem e Estacionamento'
    elif any(k in t for k in ['cinto de segurança', 'sistema de retenção', 'cadeirinha', 'airbag', 'encosto de cabeça', 'aquaplanagem', 'nevoeiro', 'chuva intensa', 'gelo', 'neve', 'triângulo', 'colete retrovisor', 'primeiros socorros', 'acidente', 'ferido']):
        return 'Segurança Rodoviária, Prevenção e Condução Defensiva'
    elif any(k in t for k in ['pontos', 'regime probatório', 'título de condução', 'carta de condução', 'seguro obrigatório', 'inspecção periódica', 'inspeção periódica', 'apreensão do veículo', 'apreensão da carta', 'cassação', 'coima', 'contraordenação', 'contra-ordenação', 'inibição de conduzir', 'crime rodoviário']):
        return 'Documentação, Regime Probatório e Regime Sancionatório'
    elif any(k in t for k in ['autoestrada', 'auto-estrada', 'via reservada', 'passagem de nível', 'peão', 'peões', 'velocípede', 'ciclista', 'prioritário', 'urgência', 'marcha de urgência', 'ambulância', 'bombeiro', 'polícia', 'cortejo']):
        return 'Vias Especiais e Outros Utentes da Via'
    elif any(k in t for k in ['sinal', 'painel', 'marca rodoviária', 'semáforo', 'cedência', 'prioridade', 'cruzamento', 'rotunda', 'ultrapass', 'inversão', 'marcha atrás', 'marcha-atrás', 'mudança de direcção', 'mudança de direção', 'faixa de rodagem', 'berma', 'eixo da faixa']):
        return 'Sinalização Rodoviária e Cedência de Passagem'
    else:
        return 'Regras Gerais de Trânsito, Circulação e Manobras'

def classify_cat_c(t):
    t = t.lower()
    if any(k in t for k in ['tacógrafo', 'tacografo', 'disco', 'repouso', 'tempo de condução', 'pausa', 'condução diária', 'condução semanal', 'cartão de condutor']):
        return 'Tacógrafo e Tempos de Condução e Repouso'
    elif any(k in t for k in ['peso bruto', 'dimensão', 'comprimento', 'altura', 'largura', 'eixo', 'tara', 'peso total', 'lotação']):
        return 'Pesos, Dimensões e Regulamentação de Pesados'
    elif any(k in t for k in ['carga', 'mercadoria', 'estiva', 'amarração', 'acondicionamento', 'centro de gravidade', 'reboque', 'semirreboque', 'semi-reboque']):
        return 'Cargas, Acondicionamento, Estiva e Reboques'
    elif any(k in t for k in ['pneumático', 'retardador', 'travão de escape', 'travões', 'compressor', 'suspensão', 'quinta roda', 'manutenção', 'motor', 'óleo', 'diferencial']):
        return 'Mecânica, Sistemas de Travagem Pneumática e Equipamentos'
    else:
        return 'Regras de Circulação, Segurança e Condução Defensiva de Pesados'

def classify_cat_d(t):
    t = t.lower()
    if any(k in t for k in ['tacógrafo', 'tacografo', 'disco', 'repouso', 'tempo de condução', 'pausa', 'horário', 'planeamento']):
        return 'Tacógrafo, Horários e Tempos de Trabalho'
    elif any(k in t for k in ['passageiro', 'lotação', 'porta', 'embarque', 'desembarque', 'bilhete', 'idoso', 'criança', 'deficien', 'mobilidade', 'queda']):
        return 'Transporte Coletivo, Lotações e Segurança de Passageiros'
    elif any(k in t for k in ['comprimento', 'largura', 'altura', 'articulado', 'eixo', 'peso bruto', 'classe i', 'classe ii', 'classe iii', 'categoria i', 'categoria ii', 'categoria iii']):
        return 'Dimensões, Pesos e Características dos Autocarros'
    elif any(k in t for k in ['extintor', 'emergência', 'socorro', 'janela', 'ventilação', 'insonorização', 'espelho', 'moedeiro', 'varão', 'bocal de engate', 'sistema']):
        return 'Mecânica, Equipamentos de Segurança e Emergência'
    else:
        return 'Condução Defensiva e Dinâmica de Autocarros'

def import_all():
    init_db()
    txt_path = 'C:/Users/candi/Desktop/teste_utf8.txt'
    with open(txt_path, 'r', encoding='utf-8') as f:
        text = f.read()

    cats_info = [
        ('A', 159, 143284, classify_cat_a),
        ('B', 143284, 925302, classify_cat_b),
        ('C', 925302, 1006811, classify_cat_c),
        ('D', 1006811, len(text), classify_cat_d)
    ]

    pattern = re.compile(r'(?:^|[\r\n\f]+)\s*(\d+)\.\s*(.*?)(?=(?:[\r\n\f]+\s*\d+\.\s*)|\Z)', re.DOTALL)
    opt_pattern = re.compile(r'(?:^|\s|\n)(✓\s*)?([A-D]\))\s*')

    conn = get_connection()
    c = conn.cursor()

    # Clear existing questions
    c.execute("DELETE FROM questions")

    total_inserted = 0
    t0 = time.time()

    for cat_code, start_idx, end_idx, cl_func in cats_info:
        seg = text[start_idx:end_idx]
        for m in pattern.finditer(seg):
            raw = m.group(2).replace('\ufeff', '').strip()
            
            # Extract question ID [#509]
            orig_id_match = re.search(r'\[#(\d+)\]', raw)
            orig_id = int(orig_id_match.group(1)) if orig_id_match else None

            opts_matches = list(opt_pattern.finditer(raw))
            if not opts_matches:
                continue

            prompt = raw[:opts_matches[0].start()].strip()
            # Remove [#ID] from prompt for cleaner display, or keep it
            clean_prompt = re.sub(r'\s*\[#\d+\]\s*$', '', prompt).strip()

            options = []
            correct_letter = None
            for i, om in enumerate(opts_matches):
                is_corr = bool(om.group(1))
                letter = om.group(2).replace(')', '').strip()
                st = om.end()
                en = opts_matches[i+1].start() if i+1 < len(opts_matches) else len(raw)
                opt_text = raw[st:en].strip()
                options.append({
                    'letter': letter,
                    'text': opt_text,
                    'is_correct': is_corr
                })
                if is_corr:
                    correct_letter = letter

            tema = cl_func(raw)

            c.execute("""
            INSERT INTO questions (original_id, categoria, tema, prompt, options, correct_letter)
            VALUES (?, ?, ?, ?, ?, ?)
            """, (
                orig_id,
                cat_code,
                tema,
                clean_prompt,
                json.dumps(options, ensure_ascii=False),
                correct_letter or 'A'
            ))
            total_inserted += 1

    conn.commit()
    conn.close()
    print(f"Imported {total_inserted} questions in {time.time() - t0:.2f} seconds!")

if __name__ == '__main__':
    import_all()
