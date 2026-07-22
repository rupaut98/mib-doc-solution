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

Runtime: Tesseract + PyMuPDF + RapidFuzz. CPU-only, no network, no LLM/VLM.
