# main.py

import logging
from telegram.ext import Application, CommandHandler, CallbackQueryHandler

from config import TELEGRAM_TOKEN
from modules.handlers import start_command, analisis_command, button_handler, history_command, lapor_command, bantuan_command
from modules.database import setup_database

def main():
    """Fungsi utama untuk merakit dan menjalankan bot."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("chimera405.log"),
            logging.StreamHandler()
        ]
    )
    
    setup_database()

    if not TELEGRAM_TOKEN or 'ANDA_DI_SINI' in TELEGRAM_TOKEN:
        logging.critical("!!! TOKEN TELEGRAM BELUM DIISI DI config.py !!!")
        return

    logging.info("Membangun Proyek Chimera405...")
    application = Application.builder().token(TELEGRAM_TOKEN).build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("analisis", analisis_command))
    application.add_handler(CommandHandler("history", history_command))
    application.add_handler(CommandHandler("lapor", lapor_command))
    application.add_handler(CommandHandler("bantuan", bantuan_command))
    application.add_handler(CallbackQueryHandler(button_handler))

    logging.info("Bot Chimera405 siap beroperasi!")
    application.run_polling()

if __name__ == "__main__":
    main()
