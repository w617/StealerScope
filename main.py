import logging
from gui import StealerScopeGUI
from settings_manager import SettingsManager

# Set up logging to file and console.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("stealerscope.log"),
        logging.StreamHandler()
    ]
)

logging.info("Application starting...")

# Initialize settings (optional use in GUI)
settings_manager = SettingsManager()

if __name__ == "__main__":
    app = StealerScopeGUI()
    app.mainloop()
