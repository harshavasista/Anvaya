import fitz  # PyMuPDF
import json
import os
import hashlib
import sqlite3
import csv
import zipfile

def generate_demo_files():
    os.makedirs('data/demo', exist_ok=True)

    # 1. Clean PDF
    doc = fitz.open()
    page = doc.new_page(width=595, height=842)  # A4
    page.insert_text((50, 72), "ANVAYA FORENSIC LABORATORY", fontsize=18, fontname="helv", color=(0.1, 0.2, 0.5))
    page.insert_text((50, 110), "Case Exhibit: EX-2026-0926-A", fontsize=12, fontname="helv")
    page.insert_text((50, 130), "Document Classification: CONFIDENTIAL / EVIDENCE", fontsize=10, fontname="helv")
    page.insert_text((50, 160), "This document contains genuine digital evidence for forensic validation.", fontsize=11, fontname="helv")
    page.insert_text((50, 180), "Paragraph 1: Transaction records confirm cryptographic verification of payload blocks.", fontsize=11, fontname="helv")
    page.insert_text((50, 200), "Paragraph 2: Integrity checksums were established at ingestion.", fontsize=11, fontname="helv")
    page.draw_rect(fitz.Rect(50, 230, 545, 300), color=(0.2, 0.4, 0.8), width=1.5)
    page.insert_text((60, 260), "AUTHENTIC CHAIN OF CUSTODY PRESERVED", fontsize=12, fontname="helv", color=(0.1, 0.5, 0.2))

    clean_pdf_bytes = doc.tobytes()
    doc.close()

    with open('data/demo/clean_evidence.pdf', 'wb') as f:
        f.write(clean_pdf_bytes)

    # 2. Corrupted PDF: Damaged xref table and truncated EOF marker
    corrupted_pdf = bytearray(clean_pdf_bytes)
    sx_idx = corrupted_pdf.rfind(b"startxref")
    if sx_idx != -1:
        for i in range(sx_idx, min(sx_idx + 35, len(corrupted_pdf))):
            corrupted_pdf[i] = ord('X')
    corrupted_pdf_bytes = bytes(corrupted_pdf[:-15])

    with open('data/demo/corrupted_evidence.pdf', 'wb') as f:
        f.write(corrupted_pdf_bytes)

    # 3. Clean JSON
    clean_json_obj = {
        "case_id": "CASE-DEMO-001",
        "investigator": "Forensic Specialist",
        "timestamp": "2026-09-26T08:00:00Z",
        "target_account": "AC-994821",
        "transaction_history": [
            {"id": "TX-101", "amount": 15000.0, "currency": "USD", "status": "SETTLED"},
            {"id": "TX-102", "amount": 42000.5, "currency": "USD", "status": "FLAGGED"}
        ],
        "audit_signature": "a8f5c3b9910d4e5a6f7b8c9d0e1f2a3b"
    }
    clean_json_str = json.dumps(clean_json_obj, indent=2)
    with open('data/demo/clean_evidence.json', 'w', encoding='utf-8') as f:
        f.write(clean_json_str)

    # 4. Corrupted JSON: Truncated syntax with unclosed string and bracket/braces
    corrupted_json_str = clean_json_str[:clean_json_str.rfind('"audit_signature"')] + '"audit_sig'
    with open('data/demo/corrupted_evidence.json', 'w', encoding='utf-8') as f:
        f.write(corrupted_json_str)

    # 5. Clean TXT
    clean_txt_content = (
        "FORENSIC WITNESS STATEMENT\n"
        "Case: INV-2026-88\n"
        "Date: September 26, 2026\n\n"
        "The digital evidence drive was acquired in a forensically sterile environment.\n"
        "Write-blocking interfaces were verified prior to physical connection.\n"
        "All observed data blocks retained original cryptographic signatures.\n"
    )
    with open('data/demo/clean_evidence.txt', 'w', encoding='utf-8') as f:
        f.write(clean_txt_content)

    # 6. Corrupted TXT: Contaminated with invalid UTF-8 bytes and null sequences
    corrupted_txt_bytes = clean_txt_content.encode('utf-8') + b"\x00\x00\xfe\xff\xc0\xaf[DAMAGED_BLOCK_0xFA]\x00\x00"
    with open('data/demo/corrupted_evidence.txt', 'wb') as f:
        f.write(corrupted_txt_bytes)

    # 7. Additional Tier 2/3 healthy samples:
    # CSV
    with open('data/demo/clean_evidence.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "IP_Address", "Action", "Status"])
        writer.writerow(["2026-09-26T01:15:00Z", "192.168.1.105", "LOGIN_ATTEMPT", "SUCCESS"])
        writer.writerow(["2026-09-26T01:18:22Z", "192.168.1.105", "TRANSFER_EXECUTE", "COMPLETED"])

    # Corrupted CSV (ragged columns, broken quote)
    with open('data/demo/corrupted_evidence.csv', 'w', encoding='utf-8') as f:
        f.write('Timestamp,IP_Address,Action,Status\n2026-09-26T01:15:00Z,192.168.1.105,LOGIN_ATTEMPT,SUCCESS\n2026-09-26T01:18:22Z,"UNCLOSED_QUOTE,EXTRA_COL_1,EXTRA_COL_2\n')

    # PNG
    # Minimal 1x1 valid PNG
    valid_png_bytes = (
        b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
        b'\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc\xf8\xff\xff'
        b'?'
        b'\x03\x05\x00\x01\x02\x00\x05\xe2\x02q\x00\x00\x00\x00IEND\xaeB`\x82'
    )
    with open('data/demo/clean_evidence.png', 'wb') as f:
        f.write(valid_png_bytes)

    # Corrupted PNG: Missing IEND chunk and damaged CRC
    with open('data/demo/corrupted_evidence.png', 'wb') as f:
        f.write(valid_png_bytes[:-12])

    # ZIP
    with zipfile.ZipFile('data/demo/clean_evidence.zip', 'w') as zf:
        zf.writestr('evidence_metadata.txt', 'Verified cryptographic archive block.')
    
    # SQLite
    db_path = 'data/demo/clean_evidence.sqlite'
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE evidence (id INTEGER PRIMARY KEY, note TEXT);")
    conn.execute("INSERT INTO evidence (note) VALUES ('Forensically acquired SQLite table');")
    conn.commit()
    conn.close()

    # Hashes & Manifest
    corrupted_pdf_sha = hashlib.sha256(corrupted_pdf_bytes).hexdigest()
    corrupted_json_sha = hashlib.sha256(corrupted_json_str.encode('utf-8')).hexdigest()
    corrupted_txt_sha = hashlib.sha256(corrupted_txt_bytes).hexdigest()

    manifest = {
        corrupted_pdf_sha: {
            "reference_file": "data/demo/clean_evidence.pdf",
            "file_type": "PDF",
            "damage_type": "DAMAGED_XREF_AND_EOF_TRUNCATION",
            "description": "PDF with damaged cross-reference table and truncated EOF marker"
        },
        corrupted_json_sha: {
            "reference_file": "data/demo/clean_evidence.json",
            "file_type": "JSON",
            "damage_type": "TRUNCATED_SYNTAX",
            "description": "JSON document truncated mid-key with missing delimiters"
        },
        corrupted_txt_sha: {
            "reference_file": "data/demo/clean_evidence.txt",
            "file_type": "TXT",
            "damage_type": "ENCODING_AND_NULL_CONTAMINATION",
            "description": "Text document contaminated with invalid byte sequences and null bytes"
        }
    }

    with open('data/demo/manifest.json', 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

    print("Demo dataset generated successfully.")
    print(f"Corrupted PDF SHA: {corrupted_pdf_sha}")
    print(f"Corrupted JSON SHA: {corrupted_json_sha}")
    print(f"Corrupted TXT SHA: {corrupted_txt_sha}")

if __name__ == '__main__':
    generate_demo_files()
