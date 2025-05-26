import sqlite3
from pathlib import Path

temporarydir=Path("D:\\pcap")

dbpath=temporarydir/'mydb.db'
conn = sqlite3.connect(str(dbpath))
cursor = conn.cursor()

# 可选：创建表（数据库文件已存在但无表时使用）
cursor = conn.cursor()

cursor.execute('CREATE TABLE users (uid INTEGER PRIMARY KEY AUTOINCREMENT, urname TEXT, passwd TEXT)')
cursor.execute('CREATE TABLE cookies (ucookie CHARACTER(16) PRIMARY KEY, user INTEGER, effectime INTEGER)')
cursor.execute('CREATE TABLE pcaps (pcapid CHARACTER(16) PRIMARY KEY, owner INTEGER,updtime TEXT,fcount INTEGER)')