# -*- coding: utf-8 -*-
"""Importa as perguntas (com imagens) dos 4 PDFs por categoria para a BD.

- Extrai o texto de cada página (pergunta N. ... [#ID], opções A/B/C/D, ✓ = correta)
- Extrai cada imagem e associa-a à pergunta cujo título aparece logo abaixo da imagem
- Guarda as imagens em static/assets/questions/<original_id>.png
- Substitui TODAS as perguntas na BD (backup automático antes)
"""
import os
import re
import json
import shutil
import hashlib
import sqlite3
import sys
import time

import pymupdf  # PyMuPDF

BASE = r'C:\Users\candi\Desktop\projecto de testes para alunos'
PROJECT = r'C:\Users\candi\Desktop\PROJECTO DE TESTES'
IMG_DIR = os.path.join(PROJECT, 'static', 'assets', 'questions')
DB_PATH = os.path.join(PROJECT, 'carta_auto_testes.db')
SEED_PATH = os.path.join(PROJECT, 'seed', 'carta_auto_testes_seed.db')

PDFS = {
    'A': os.path.join(BASE, 'testes_codigo_categoria_A_com_imagens.pdf'),
    'B': os.path.join(BASE, 'testes_codigo_categoria_B_com_imagens.pdf'),
    'C': os.path.join(BASE, 'testes_codigo_categoria_C_com_imagens.pdf'),
    'D': os.path.join(BASE, 'testes_codigo_categoria_D_com_imagens.pdf'),
}

sys.path.insert(0, PROJECT)
from import_questions import classify_cat_a, classify_cat_b, classify_cat_c, classify_cat_d

CLASSIFIERS = {'A': classify_cat_a, 'B': classify_cat_b, 'C': classify_cat_c, 'D': classify_cat_d}

os.makedirs(IMG_DIR, exist_ok=True)

qnum_re = re.compile(r'^(\d+)\.\s', re.M)
id_re = re.compile(r'\[#(\d+)\]')
opt_re = re.compile(r'(✓\s*)?([A-D]\))\s*')


def parse_pdf(cat, path):
    doc = pymupdf.open(path)
    questions = {}   # original_id -> dict
    img_cache = {}   # xref -> saved filename
    page_headings = []  # per page: list of (y, qnum, orig_id)
    page_imgs = []      # per page: list of (xref, bbox)
    stats = {'pages': 0, 'images': 0, 'saved_imgs': 0}

    for pno in range(len(doc)):
        page = doc[pno]
        stats['pages'] += 1
        text = page.get_text('text')
        headings = []
        blocks = page.get_text('blocks')
        for b in blocks:
            m = re.match(r'\s*(\d+)\.\s', b[4])
            if m:
                idm = id_re.search(b[4])
                if idm:
                    headings.append((b[1], int(m.group(1)), int(idm.group(1))))
        page_headings.append(headings)
        page_imgs.append([(i['xref'], i['bbox']) for i in page.get_image_info(xrefs=True)])

        # Parse question text (full page text, joined)
        for m in re.finditer(r'(?ms)^(\d+)\.\s(.*?)(?=^\d+\.\s|\Z)', text):
            qnum = int(m.group(1))
            raw = m.group(2).replace('\ufeff', '').strip()
            idm = id_re.search(raw)
            if not idm:
                continue
            orig_id = int(idm.group(1))
            opts_matches = list(opt_re.finditer(raw))
            if not opts_matches:
                continue
            prompt = re.sub(r'\s*\[#\d+\]\s*', ' ', raw[:opts_matches[0].start()]).strip()
            prompt = re.sub(r'\s+', ' ', prompt)
            options = []
            correct_letter = None
            for i, om in enumerate(opts_matches):
                is_corr = bool(om.group(1))
                letter = om.group(2)[0]
                st = om.end()
                en = opts_matches[i + 1].start() if i + 1 < len(opts_matches) else len(raw)
                opt_text = re.sub(r'\s+', ' ', raw[st:en].strip())
                opt_text = re.sub(r'\s*\[#\d+\]\s*', ' ', opt_text).strip()
                options.append({'letter': letter, 'text': opt_text, 'is_correct': is_corr})
                if is_corr:
                    correct_letter = letter
            entry = questions.setdefault(orig_id, {})
            entry.update({
                'original_id': orig_id,
                'categoria': cat,
                'prompt': prompt,
                'options': options,
                'correct_letter': correct_letter or 'A',
                '_num': qnum,
            })

    # Second pass: assign images to question headings (now all texts parsed)
    for pno in range(len(doc)):
        pass  # doc closed later; handled below
    doc2 = pymupdf.open(path)
    for pno in range(len(doc2)):
        page = doc2[pno]
        headings = page_headings[pno]
        for xref, bbox in page_imgs[pno]:
            img_bottom = bbox[3]
            below = [h for h in headings if h[0] > img_bottom]
            if not below:
                continue
            target = min(below, key=lambda h: h[0])
            orig_id = target[2]
            q = questions.get(orig_id)
            if q is None or q.get('image_path'):
                continue
            stats['images'] += 1
            if xref not in img_cache:
                try:
                    pix = pymupdf.Pixmap(doc2, xref)
                    if pix.n - pix.alpha > 3:
                        pix = pymupdf.Pixmap(pymupdf.csRGB, pix)
                    fname = f'{cat}_{orig_id}.png'
                    pix.save(os.path.join(IMG_DIR, fname))
                    img_cache[xref] = fname
                    stats['saved_imgs'] += 1
                except Exception as e:
                    print('img error', cat, xref, e)
                    continue
            q['image_path'] = img_cache[xref]
    doc2.close()
    doc.close()
    return questions, stats


def main():
    # Backup DB
    stamp = time.strftime('%Y%m%d_%H%M%S')
    bak = DB_PATH + f'.backup_{stamp}'
    shutil.copy2(DB_PATH, bak)
    print('Backup:', bak)

    all_q = {}
    for cat, path in PDFS.items():
        qs, st = parse_pdf(cat, path)
        print(f'Cat {cat}: pages={st["pages"]} imgs_placed={st["images"]} imgs_saved={st["saved_imgs"]} questions={len(qs)}')
        all_q[cat] = qs

    total = sum(len(v) for v in all_q.values())
    with_img = sum(1 for v in all_q.values() for q in v.values() if q.get('image_path'))
    print(f'TOTAL: {total} questions, {with_img} com imagem')

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('PRAGMA foreign_keys = ON')
    c.execute('DELETE FROM questions')
    n = 0
    missing_prompt = 0
    for cat, qs in all_q.items():
        cl = CLASSIFIERS[cat]
        for orig_id, q in qs.items():
            if not q.get('prompt') or not q.get('options'):
                missing_prompt += 1
                continue
            tema = cl(q['prompt'])
            c.execute(
                'INSERT INTO questions (original_id, categoria, tema, prompt, options, correct_letter, image_path) VALUES (?,?,?,?,?,?,?)',
                (orig_id, cat, tema, q['prompt'], json.dumps(q['options'], ensure_ascii=False), q['correct_letter'], q.get('image_path'))
            )
            n += 1
    conn.commit()
    conn.close()
    print(f'Inserted {n} questions (skipped {missing_prompt} without parsed text).')

    # Also refresh seed DB if it exists
    if os.path.exists(SEED_PATH):
        shutil.copy2(DB_PATH, SEED_PATH)
        print('Seed DB updated:', SEED_PATH)


if __name__ == '__main__':
    main()
