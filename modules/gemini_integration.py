# modules/gemini_integration.py
import google.generativeai as genai
from config import GEMINI_API_KEY
import logging

logger = logging.getLogger(__name__)

def generate_final_verdict(analysis_data: dict):
    if not GEMINI_API_KEY or 'ANDA_DI_SINI' in GEMINI_API_KEY:
        return "Fitur analisis AI belum aktif. Harap isi GEMINI_API_KEY di file config.py."

    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-pro')

    prompt = f"""
    Anda adalah seorang analis keamanan cryptocurrency yang sangat berpengalaman dan skeptis.
    Tugas Anda adalah memberikan verdict akhir tentang potensi scam dari sebuah proyek berdasarkan data mentah yang saya berikan.
    Berikan jawaban dalam format Markdown, mulai dengan kesimpulan (misal: SANGAT BERISIKO TINGGI), diikuti dengan ringkasan, lalu penjelasan detail dari setiap poin temuan.
    Gunakan bahasa yang tegas, jelas, dan mudah dimengerti untuk pengguna awam.

    Berikut adalah data temuannya:
    - Nama Proyek: {analysis_data.get('name', 'Tidak Diketahui')}
    - Target Analisis: {analysis_data.get('target')}
    - Skor Bahaya Terhitung: {analysis_data.get('score', 0)}
    - Temuan-temuan Kunci:
    """
    
    for reason in analysis_data.get('reasons', []):
        prompt += f"\n    - {reason}"
        
    prompt += "\n\nBerikan verdict akhir Anda sekarang."

    try:
        logger.info("Mengirim permintaan ke Gemini AI...")
        response = model.generate_content(prompt)
        logger.info("Respon dari Gemini AI diterima.")
        return response.text
    except Exception as e:
        logger.error(f"Error saat menghubungi Gemini API: {e}")
        return f"Gagal menghubungi konsultan AI (Gemini). Error: {e}\n\nBerikut adalah data mentahnya:\n" + "\n".join(analysis_data.get('reasons', []))
