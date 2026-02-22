#!/usr/bin/env python3
import pandas as pd

# Substitua pelo caminho do seu ficheiro
file_path = 'nist.sp.800-218.ssdf-table.xlsx - SSDF.csv'
df = pd.read_csv(file_path)

# Formata as quebras de linha para Markdown
def format_for_markdown(text):
    if isinstance(text, str):
        return text.replace('\n', '<br>')
    return text

df_formatted = df.applymap(format_for_markdown)

# Gera e guarda o ficheiro Markdown
markdown_table = df_formatted.to_markdown(index=False)
with open('nist_ssdf_table.md', 'w', encoding='utf-8') as f:
    f.write(markdown_table)

print("Ficheiro nist_ssdf_table.md criado com sucesso!")