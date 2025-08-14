import yara
import os
import json

# Carpeta donde tienes las reglas YARA que seleccionaste
RULES_DIR = os.path.join(os.path.dirname(__file__), 'YARA')

# Archivo donde se guardarán los strings extraídos
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), 'strings_extracted.json')

# Lista de reglas específicas que quieres procesar (sin extensiones)
RULES_TO_INCLUDE = [
    "Email_generic_phishing",
    "extortion_email",
    "Maldoc_VBA_macro_code",
    "Maldoc_PDF",
    "Maldoc_Dridex",
    "WShell_ChinaChopper",
    "EK_Zeus"
]

def extract_strings_from_rule(rule):
    strings = []
    # rule.strings es lista de tuplas (offset, id, value_bytes)
    for _, _, value in rule.strings:
        try:
            s = value.decode('utf-8', errors='ignore').strip()
            if s:
                strings.append(s)
        except Exception:
            pass
    return strings

def main():
    all_strings = {}

    for filename in os.listdir(RULES_DIR):
        if filename.endswith('.yar') or filename.endswith('.yara'):
            # Nombre base sin extensión para comparar con lista
            base_name = os.path.splitext(filename)[0]

            if base_name not in RULES_TO_INCLUDE:
                continue

            filepath = os.path.join(RULES_DIR, filename)

            try:
                rules = yara.compile(filepath)
                for rule in rules:
                    # Cada rule es un objeto Rule
                    # El nombre de la regla .identifier
                    rule_name = rule.identifier
                    if rule_name not in all_strings:
                        all_strings[rule_name] = []

                    # Extraemos strings
                    strs = extract_strings_from_rule(rule)
                    all_strings[rule_name].extend(strs)

            except Exception as e:
                print(f"[ERROR] Compiling {filename}: {e}")

    # Guardar a JSON
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(all_strings, f, indent=2, ensure_ascii=False)

    print(f"[+] Extraídas cadenas de {len(all_strings)} reglas y guardadas en {OUTPUT_FILE}")

if __name__ == '__main__':
    main()
