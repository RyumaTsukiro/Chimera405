# modules/handlers.py
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from telegram.constants import ParseMode
import requests, logging
from datetime import datetime

from . import database as db
from . import analysis_tools as tools
from . import gemini_integration

logger = logging.getLogger(__name__)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_message = (
        "🏆 **Chimera405 Definitive Edition** 🏆\n\n"
        "Bot analis kripto berbasis AI. Gunakan tombol di bawah atau ketik perintah untuk memulai."
    )
    keyboard = [
        [InlineKeyboardButton("🚀 Analisis Proyek Baru", callback_data='main_analyze')],
        [InlineKeyboardButton("📚 Lihat Riwayat Analisis", callback_data='main_history')],
        [InlineKeyboardButton("❓ Bantuan & Info", callback_data='main_help')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(welcome_message, reply_markup=reply_markup)

async def bantuan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    help_text = (
        "*Bantuan Bot Chimera405*\n\n"
        "Perintah yang tersedia:\n\n"
        "*/analisis [nama proyek]*\n"
        "Memulai investigasi. Contoh: `/analisis dogecoin`\n\n"
        "*/history*\n"
        "Menampilkan 10 riwayat analisis terakhir.\n\n"
        "*/lapor [kontrak] [alasan]*\n"
        "Melaporkan kontrak scam untuk membantu komunitas.\n"
        "Contoh: `/lapor 0x... token palsu`"
    )
    await update.message.reply_text(help_text, parse_mode=ParseMode.MARKDOWN)

async def analisis_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        query = " ".join(context.args).lower()
        if not query:
            await update.message.reply_text("Masukin nama proyeknya, Bos. Contoh: `/analisis uniswap`")
            return
    except IndexError:
        await update.message.reply_text("Format salah.")
        return

    msg = await update.message.reply_text(f"Mencari data resmi untuk *{query.title()}* di CoinGecko...", parse_mode=ParseMode.MARKDOWN)
    try:
        search_url = f"https://api.coingecko.com/api/v3/search?query={query}"
        search_res = requests.get(search_url).json()
        if not search_res.get('coins'):
            await msg.edit_text(f"Nggak nemu proyek dengan nama '{query}' di CoinGecko.")
            return
        
        coin_id = search_res['coins'][0]['id']
        coin_data_url = f"https://api.coingecko.com/api/v3/coins/{coin_id}"
        data = requests.get(coin_data_url).json()

        website = data.get('links', {}).get('homepage', [None])[0]
        contract_address = data.get('platforms', {}).get('binance-smart-chain') or data.get('platforms', {}).get('ethereum') or next((v for k, v in data.get('platforms', {}).items() if v), None)

        context.user_data.update({
            'website': website,
            'contract': contract_address,
            'chain': 'bsc' if contract_address == data.get('platforms', {}).get('binance-smart-chain') else 'eth',
            'name': data.get('name')
        })

        report = f"✅ Data resmi untuk *{data.get('name')}* ditemukan!\n\n"
        if website: report += f"🔗 **Website:** `{website}`\n"
        if contract_address: report += f"📜 **Kontrak:** `{contract_address}`\n"
        report += "\nSilakan pilih target investigasi:"

        keyboard = [
            [InlineKeyboardButton("🔬 Analisis Link Website", callback_data='analyze_link')] if website else [],
            [InlineKeyboardButton("📜 Analisis Kontrak Token", callback_data='analyze_contract')] if contract_address else []
        ]
        
        if not any(keyboard):
            await msg.edit_text(f"Data ditemukan untuk *{data.get('name')}*, tapi tidak ada website atau alamat kontrak yang bisa dianalisis dari CoinGecko.")
            return

        reply_markup = InlineKeyboardMarkup(keyboard)
        await msg.edit_text(report, reply_markup=reply_markup, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    except Exception as e:
        logger.error(f"Error di analisis_command: {e}")
        await msg.edit_text("Waduh, ada error pas nyari data. Coba lagi nanti.")

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    choice = query.data
    
    # Logika Tombol Menu Utama
    if choice == 'main_analyze':
        await query.message.reply_text("Silakan ketik perintah `/analisis [nama proyek]` untuk memulai investigasi.\nContoh: `/analisis ethereum`")
        return
    if choice == 'main_history':
        await history_command(update, context); return
    if choice == 'main_help':
        await bantuan_command(update, context); return

    name = context.user_data.get('name', 'Proyek Ini')
    risk_level = "ERROR"; score = -1; target_id = "N/A"
    
    if choice == 'analyze_link':
        url = context.user_data.get('website')
        if not url: await query.message.edit_text("URL tidak ditemukan."); return
        await query.message.edit_text(f"Oke, menjalankan forensik link untuk *{name}* dan berkonsultasi dengan AI...", parse_mode=ParseMode.MARKDOWN)
        
        target_id, score, reasons = url, 0, []
        vt_result = tools.check_virustotal(url)
        if vt_result['malicious'] > 0: score += 100; reasons.append(f"BLACKLIST VIRUSTOTAL: Terdeteksi berbahaya oleh **{vt_result['malicious']}** mesin keamanan.")
        elif vt_result['suspicious'] > 0: score += 40; reasons.append(f"MENCURIGAKAN: Terdeteksi 'mencurigakan' oleh **{vt_result['suspicious']}** mesin keamanan.")
        else: reasons.append("Lolos pemindaian VirusTotal (0 deteksi).")

        if tools.scrape_page_content(url)['seed_phrase_mention']: score += 200; reasons.append("FATAL: Halaman ini meminta Seed Phrase!")
        
        domain_age = tools.get_domain_age(url)
        if domain_age != -1 and domain_age < 30: score += 30; reasons.append(f"DOMAIN BARU: Umur baru `{domain_age}` hari.")
        elif domain_age != -1: reasons.append(f"UMUR DOMAIN: {domain_age} hari.")
        else: reasons.append("Umur domain tidak dapat ditentukan.")
        
        if score >= 200: risk_level = "PHISHING PASTI"
        elif score >= 100: risk_level = "SANGAT TINGGI"
        elif score >= 40: risk_level = "TINGGI"
        else: risk_level = "RENDAH"

    elif choice == 'analyze_contract':
        contract = context.user_data.get('contract')
        chain = context.user_data.get('chain', 'bsc')
        if not contract: await query.message.edit_text("Alamat kontrak tidak ditemukan."); return
        await query.message.edit_text(f"Oke, menjalankan investigasi gabungan untuk *{name}* dan berkonsultasi dengan AI...", parse_mode=ParseMode.MARKDOWN)
        
        target_id, score, reasons = contract, 0, []
        
        if db.check_reported_status(contract): report = db.check_reported_status(contract); score += 150; reasons.append(f"DILAPORKAN SCAM oleh {report[1]}: {report[0]}")
        if tools.check_honeypot(contract): score += 100; reasons.append("TERDETEKSI HONEYPOT!")
        if not tools.get_contract_verification(contract, chain): score += 30; reasons.append("Kontrak Tidak Terverifikasi.")
        else: reasons.append("Kontrak Terverifikasi.")
        
        top_10 = tools.scrape_token_holders(contract, chain)['top_10_hold_percentage']
        if top_10 > 50: score += 40; reasons.append(f"Distribusi Buruk! ({top_10:.1f}% dipegang 10 dompet teratas).")
        elif top_10 > 0: reasons.append(f"Distribusi Baik ({top_10:.1f}% dipegang 10 dompet teratas).")
        else: reasons.append("Data distribusi holder tidak dapat diambil.")

        debank_info = tools.get_debank_info(contract, chain)
        if debank_info:
            if debank_info['is_core']: reasons.append("STATUS (DeBank): Diakui sebagai Aset Inti protokol.")
            if debank_info['chain_count'] > 1: reasons.append(f"MULTI-CHAIN (DeBank): Terdeteksi di **{debank_info['chain_count']}** blockchain.")
        
        if score >= 100: risk_level = "SANGAT TINGGI"
        elif score >= 50: risk_level = "TINGGI"
        elif score >= 30: risk_level = "SEDANG"
        else: risk_level = "RENDAH"

    analysis_data = {'target': target_id, 'score': score, 'reasons': reasons, 'name': name}
    final_report = gemini_integration.generate_final_verdict(analysis_data)
    await query.message.edit_text(final_report, parse_mode=ParseMode.MARKDOWN, disable_web_page_preview=True)
    db.add_analysis_to_history(choice.replace('analyze_', ''), target_id, risk_level, score, final_report)

async def history_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    history_data = db.get_history()
    if not history_data:
        await update.message.reply_text("Belum ada riwayat analisis.")
        return
    response = "*Riwayat 10 Analisis Terakhir:*\n\n"
    for item in history_data:
        timestamp_str, risk, type, identifier = item
        dt_obj = datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        response += f"`{dt_obj.strftime('%Y-%m-%d %H:%M')}` - *{risk}* - {type.title()}: `{identifier[:20]}...`\n"
    await update.message.reply_text(response, parse_mode=ParseMode.MARKDOWN)

async def lapor_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        contract = context.args[0]
        reason = " ".join(context.args[1:])
        if not contract.startswith('0x') or len(contract) != 42 or not reason:
            await update.message.reply_text("Format salah.\nContoh: `/lapor 0x... terbukti rugpull`")
            return
        user = update.effective_user.username or update.effective_user.first_name
        if db.add_report(contract, reason, user):
            await update.message.reply_text("✅ Laporan diterima! Terima kasih atas kontribusi Anda.")
        else:
            await update.message.reply_text("⚠️ Kontrak ini sudah pernah dilaporkan sebelumnya.")
    except IndexError:
        await update.message.reply_text("Format salah.\nContoh: `/lapor 0x... terbukti rugpull`")
