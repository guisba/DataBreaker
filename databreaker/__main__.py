from __future__ import annotations
import threading, webbrowser
import uvicorn

def open_browser(): webbrowser.open("http://127.0.0.1:8732")

def main():
    threading.Timer(1.0,open_browser).start()
    uvicorn.run("databreaker.app:app",host="127.0.0.1",port=8732,log_level="warning")

if __name__=="__main__": main()
