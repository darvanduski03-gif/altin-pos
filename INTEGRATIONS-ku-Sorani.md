# ALTIN integrations

- Cloudflare Pages hosts the frontend and Worker.
- Cloudflare D1 stores the system's backend data through the `DB` binding.
- The frontend uses SheetJS for Excel import and lazy-loads ZXing from public CDNs as a barcode-scanning fallback.
- No OpenAI/ChatGPT API integration is present in the uploaded source files reviewed for this package.
- Native GitHub-triggered deployment depends on Cloudflare Pages having an authorized GitHub repository connection. Do not put secrets or tokens in this repository.
