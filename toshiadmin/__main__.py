import os
from toshiadmin.app import app

if __name__ == "__main__":
    port = os.getenv("PORT", 8000)
    app.run(host="0.0.0.0", port=port)
