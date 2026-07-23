# mib-doc-solution

Offline document pipeline for the [MIB Doc Challenge](https://github.com/8090-inc/mib-doc-challenge):
trusted-text extraction with adversarial-span filtering, targeted Tesseract OCR,
closed-vocabulary normalization, and a mined rule cascade for adjudication.
Details in [MEMO.md](MEMO.md).

## Run

```bash
docker build -t mib-submission .
docker run --rm --network none \
  --mount type=bind,src=/path/to/pdfs,dst=/input,readonly \
  --mount type=bind,src=/path/to/out,dst=/output \
  mib-submission /input /output/predictions.jsonl
```

Runtime: CPU only, offline, no LLM or VLM. Four dependencies, each load-bearing:

- PyMuPDF reads the native text layer with span styling (which is how hidden/injected text gets dropped) and rasterizes pages
- pytesseract/Tesseract OCRs the roughly 30% of pages that are image-only
- Pillow does the grayscale and binarization preprocessing in between
- RapidFuzz snaps OCR-noisy values onto the closed field vocabularies

Local run (needs `tesseract` on PATH): `pip install -r requirements.txt && python mib.py <pdf_dir> <out.jsonl>`
