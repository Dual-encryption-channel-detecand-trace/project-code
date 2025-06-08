from flask import Flask,request,make_response,render_template,send_file,jsonify,url_for,Blueprint
from pathlib import Path
import random
import string
from module.TlsCnnModel import TlsCnnModel as myAI
from module.getdetail import getdetail
import asyncio
from module.obfsmodel import ObfsCNNClassifier,detect_on_directory
import json
import sqlite3
from module.splitpcap import split_pcap_by_ip 

import torch

modeldir=r"D:\DTDEC\project-code\code\module\obfs_cnn_model.pth"

# 页面初始设置
app=Flask(__name__)
app.debug=1
filedir=Path(__file__).parent
temporarydir=Path(r"D:\pcap")
if not (temporarydir/"temporary").exists():
    (temporarydir/"temporary").mkdir()

# 数据库
dbpath=temporarydir/'mydb.db'
if not dbpath.exists():
    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()

    cursor.execute('CREATE TABLE users (uid INTEGER PRIMARY KEY AUTOINCREMENT, urname TEXT, passwd TEXT)')
    cursor.execute('CREATE TABLE cookies (ucookie CHARACTER(16) PRIMARY KEY, user INTEGER, effectime INTEGER)')
    cursor.execute('CREATE TABLE pcaps (pcapid CHARACTER(16) PRIMARY KEY, owner INTEGER,updtime TEXT,fcount INTEGER)')
    conn.close()
    

# 食用函数
# 随机字符串
def randstr(len):
    """
    随机字符串
    """
    return ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(len))

def checkucookie(ucookie):
    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()
    cursor.execute("SELECT effectime FROM cookies WHERE ucookie = ?",(ucookie,))
    quecoo=cursor.fetchone()
    if quecoo==None:
        conn.close()
        return False
    effectime=quecoo[0]
    cursor.execute("SELECT unixepoch('now') ")
    nowtime=cursor.fetchone()[0]
    if(nowtime>effectime):
        cursor.execute("DELETE FROM cookies WHERE ucookie = ?",(ucookie,))
        conn.commit()
        conn.close()
        return False
    conn.close()
    return True

def groupbytormeek(result):
    i=0
    j=len(result)-1
    while i<j:
        while i<j and result[j]['result']=='normal':
            j=j-1
        while i<j and result[i]['result']=='tormeek':
            i=i+1
        if i<j:
            result[i],result[j]=result[j],result[i]
    
    for filedetail in result:
        filedetail=filedetail['pcapdetail']
        i=0
        j=len(filedetail)-1
        while i<j:
            while i<j and filedetail[j]['result']=='normal':
                j=j-1
            while i<j and filedetail[i]['result']=='tormeek':
                i=i+1
            filedetail[i],filedetail[j]=filedetail[j],filedetail[i]

def checkpcapowner(ucookie,pcapid):
    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()
    cursor.execute("SELECT user FROM cookies WHERE ucookie = ?",(ucookie,))
    uid=cursor.fetchone()[0]
    cursor.execute("SELECT owner FROM pcaps WHERE pcapid = ?",(pcapid,))
    owner=cursor.fetchone()[0]
    if(uid!=owner):
        conn.close()
        return False
    conn.close()
    return True

# 后端验证文件函数
def checkfile(file):
    """
    后端验证文件函数
    仅传入file
    """
    if len(file.filename)>=1 and file.filename[-1:]==".":
        return False
    if len(file.filename)>=7 and file.filename[-7:]=="::$data":
        return False
    return True

# 页面
# 初始界面
@app.route("/")
@app.route("/index")
def index():
    """
    进入页面路由
    """
    return render_template("index.html.j2",debug=app.debug)

# 上传
@app.route("/upload")
def upload():
    """
    上传页面路由
    """
    return render_template("upload.html.j2",debug=app.debug)

# 展示
# 先准备一个AI
myai=myAI()
# 实际上应该每个线程一个
# 但是每个线程分配一个太慢了

# @app.route("/user")
# def user():
#     return render_template("user.html.j2",debug=app.debug)
@app.route("/login")
def login():
    return render_template("login.html.j2",debug=app.debug)

@app.route("/history")
def history():
    return render_template("history.html.j2",debug=app.debug)

@app.route("/register")
def register():
    return render_template("register.html.j2",debug=app.debug)

@app.route("/show")
def show():
    """
    报告页面路由
    """
    ucookie=request.cookies.get("ucookie")
    if not checkucookie(ucookie):
        return jsonify(fail="please relogin"),401
    return render_template("show.html.j2",debug=app.debug)

# 食用功能
# 向前端传输文件
@app.route("/download")
def download():
    """
    前端抓后端文件
    功能路由
    """
    filename=request.args.get("filename")
    return send_file("source"+filename)

# 前端上传pcap文件
@app.route("/do/uploadpcap",methods=["GET","POST"])
def uploadpcap():
    """
    前端上传文件
    功能路由
    """
    ucookie=request.cookies.get("ucookie")
    if not checkucookie(ucookie):
        "please relogin",401
    temdir=temporarydir/"temporary"
    
    chunk = request.files['chunk']
    chunkinfo = json.loads(request.form['chunkInfo'])
    fileplace=chunkinfo['fileplace']
    filename=chunkinfo['filename']
    temp_dir=temporarydir/"temporary"/fileplace
    if not temp_dir.exists():
        temp_dir.mkdir()
    chunkdir=temp_dir/(filename+'dir')
    if not chunkdir.exists():
        chunkdir.mkdir()
    # 保存分片
    chunk.save(str(chunkdir/str(chunkinfo['id'])))
    
    # 单文件上传完成
    if len(list(chunkdir.rglob("*")))==chunkinfo['count']:
        # 合并文件
        with open(temp_dir/filename,'wb') as f:
            for i in range(len(list(chunkdir.rglob("*")))):
                with open(chunkdir/str(i), 'rb') as chunk_file:
                    f.write(chunk_file.read())
        for f in chunkdir.rglob("*"):
            f.unlink()
        chunkdir.rmdir()
        if len(list(temp_dir.rglob("*.pcap")))==chunkinfo['fcount']:
            conn = sqlite3.connect(str(dbpath))
            cursor = conn.cursor()
            cursor.execute("SELECT user FROM cookies WHERE ucookie=?",(ucookie,))
            uid=cursor.fetchone()[0]
            cursor.execute("SELECT datetime('now','+8 hours')")
            updtime=cursor.fetchone()[0]
            cursor.execute("INSERT INTO pcaps (pcapid,owner,updtime,fcount) VALUES(?,?,?,?)",(fileplace,uid,updtime,chunkinfo['fcount'],))
            conn.commit()
            conn.close()
    return jsonify(fid=chunkinfo['fid'])

# 获取信息
pcaplock=[]

@app.route("/do/runai",methods=['GET','POST'])
def runai():
    """
    运行AI
    功能路由
    """
    # 获取灵饰位置
    fileplace=request.json.get("fileplace")                                  # 获取访问位置
    if fileplace in pcaplock:
        return "run_ing",204
    
    loop=asyncio.new_event_loop()                                                # pyshark太傻了，没有loop就不跑了
    asyncio.set_event_loop(loop)

    dir=temporarydir/"temporary"/fileplace                                       # 得到实际路径
    result_file=dir/"result.json"                                                # 结果文件
    
    if result_file.exists():
        return "haveresult",204
    
    pcaplock.append(fileplace)                                                       # 上锁
    
    for f in dir.iterdir():
        if f.is_file() and f.suffix=='.pcap':
            split_pcap_by_ip(f.name,dir)
    myai=myAI()
    # 从灵石位置获取pcap文件
    result=[]
    usage=torch.device("cuda" if torch.cuda.is_available() else "cpu")
    obfsai=ObfsCNNClassifier().to(usage)
    obfsai.load_state_dict(torch.load(modeldir, map_location=usage))
    obfsresult=detect_on_directory(obfsai,dir,usage)
    for f in dir.iterdir():
        if f.is_dir():
            files=f.glob("*")
            files=list(map(lambda x:str(x),files))
            fileresult=myai.detect(files)
            fileresult_=[]
            filetype=[]
            for idx,linkfile in enumerate(files):
                filename=Path(files[idx]).name
                # fileobfsresult=obfsresult[filename]
                linkfile=Path(linkfile)
                linkresult={}
                ippair=linkfile.stem
                linkresult["srcip"]=ippair.split("-")[0]
                linkresult["dstip"]=ippair.split("-")[1]
                linktype=[]
                if fileresult[0][idx] !=0:
                    linktype.append("tormeek")
                    if "tormeek" not in filetype:
                        filetype.append("tormeek")
                # if fileobfsresult[0]=="obfs":
                #     linktype.append("obfs")
                #     if "obfs" not in filetype:
                #         filetype.append("obfs")
                linkresult["result"]='&'.join(linktype)
                if linkresult["result"]=="":
                    linkresult["result"]="normal"
                linkresult["linkdetail"]={}
                linkresult["linkdetail"]["protoflow"]=getdetail(linkfile)
                linkresult["linkdetail"]["meekfeature"]=[]
                for feature in fileresult[2][idx]:
                    linkresult["linkdetail"]["meekfeature"].append(float(feature))
                linkresult["countflow"]=linkfile.stat().st_size
                fileresult_.append(linkresult.copy())
            fileresult={}
            fileresult["pcapdetail"]=fileresult_
            fileresult["filename"]=f.name+".pcap"
            fileresult["countlink"]=len(files)
            fileresult["countflow"]=sum(ff.stat().st_size for ff in f.rglob("*"))
            if fileresult["filename"] in obfsresult and obfsresult[fileresult["filename"]][0]!="normal":
                filetype.append(obfsresult[fileresult["filename"]][0])
            fileresult["result"]="&".join(filetype)
            if fileresult["result"]=="":
                fileresult["result"]="normal"
            # fileresult['result']=("tormeek" if filetype!=False else "normal")
            result.append(fileresult.copy())
    groupbytormeek(result)
    with open(result_file,"w") as f:                                             # 导出结果到文件
        json.dump(result,f)
    
    pcaplock.remove(fileplace)                                                       # 解锁
    if not app.debug:
        for f in dir.rglob('*.pcap'):
            f.unlink()
        for f in dir.iterdir():
            if f.is_dir():
                f.rmdir()
    loop.close()
    return "OK",204

@app.route("/do/getinfo",methods=['GET','POST'])
def getinfo():
    """
    获取信息
    功能路由
    """
    ucookie=request.cookies.get("ucookie")
    if(not checkucookie(ucookie)):
        "please relogin",401
    fileplace=request.json.get("fileplace")                                  # 获取访问位置
    if(not checkpcapowner(ucookie,fileplace)):
        "worry user",401
    # 是否还在运行
    if fileplace in pcaplock:
        return jsonify(fail="run_ing"),202
    dir=temporarydir/"temporary"/fileplace                                       # 得到实际路径
    result_file=dir/"result.json"                                                # 结果文件
    if not result_file.exists():
        return jsonify(fail="no_result"),204

    result=None
    with open(result_file,"r") as f:                                         # 导出结果到文件
        result=json.load(f)
    return jsonify(result=result)
    # 从零时位置检测是否已存在结果文件
    # 获取结果
    # 获取信息（特征、流量、pkt等）
    # 整理、发送

@app.route("/do/login",methods=['GET','POST'])
def do_login():
    """
    登录
    功能路由
    """
    urname=request.json.get("urname")
    passwd=request.json.get("passwd")

    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()
    cursor.execute("SELECT uid,urname,passwd FROM users WHERE urname = ?", (urname,))
    
    queres=cursor.fetchone()
    if(queres==None):
        conn.close()
        return "again",401

    if(passwd!=queres[2]):
        conn.close()
        return "again",401
    
    uid=queres[0]
    cursor.execute("DELETE FROM cookies WHERE user = ? ", (uid,))
    cookieexist=True
    while(cookieexist):
        ucookie=randstr(16)
        cursor.execute("SELECT * FROM cookies WHERE ucookie = ? ", (ucookie,))
        quecoo=cursor.fetchone()
        if(quecoo==None):
            cookieexist=False
    
    cursor.execute("SELECT unixepoch('now','+3 days') ")
    effectime=cursor.fetchone()[0]
    cursor.execute("INSERT INTO cookies (ucookie,user,effectime) VALUES( ? , ? , ? ) ",(ucookie,uid,effectime))
    conn.commit()
    conn.close()

    response=make_response(jsonify(success="success"))
    response.set_cookie('ucookie',ucookie,max_age=3*24*3600,path='/')
    return response
    # 连接数据库，查询是否存在
    # if exist
    # return

@app.route("/do/register",methods=['GET','POST'])
def do_register():
    """
    注册
    功能路由
    """
    urname=request.json.get("urname")
    passwd=request.json.get("passwd")

    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE urname = ? ", (urname,))
    queres=cursor.fetchone()
    if(queres!=None):
        conn.close()
        return "exist",403
    cursor.execute("INSERT INTO users (urname,passwd) VALUES( ? , ? ) ",(urname,passwd))
    cursor.execute("SELECT * FROM users WHERE urname = ? ", (urname,))
    queres=cursor.fetchall()
    conn.commit()
    conn.close()
    return jsonify(success="success")

@app.route("/do/userinfo",methods=['GET','POST'])
def do_getuserinfo():
    ucookie=request.cookies.get("ucookie")
    if not checkucookie(ucookie) :
        return jsonify(unsuccess="please relogin"),401
    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()
    cursor.execute("SELECT user FROM cookies WHERE ucookie = ? ",(ucookie,))
    uid=cursor.fetchone()[0]
    cursor.execute("SELECT uid FROM users WHERE uid= ? ",(uid,))
    quepcp=cursor.fetchone()
    userinfo={'uid':quepcp[0]}
    conn.close()
    return jsonify(userinfo=userinfo)

@app.route("/do/gethistory",methods=['GET','POST'])
def do_gethistory():
    ucookie=request.cookies.get("ucookie")
    if not checkucookie(ucookie):
        return jsonify(unsuccess="please relogin"),401
    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()
    cursor.execute("SELECT user FROM cookies WHERE ucookie = ? ",(ucookie,))
    uid=cursor.fetchone()[0]
    cursor.execute("SELECT pcapid, updtime, fcount FROM pcaps WHERE owner= ? ORDER BY updtime DESC ",(uid,))
    quepcp=cursor.fetchall()
    history=[{'fileplace': item[0], 'updtime' : item[1], 'fcount' :item[2] } for item in quepcp]
    conn.close()
    return jsonify(history=history)

@app.route("/do/logout",methods=['GET','POST'])
def logout():
    ucookie=request.cookies.get("ucookie")
    conn = sqlite3.connect(str(dbpath))
    cursor = conn.cursor()
    cursor.execute("DELETE FROM cookies WHERE ucookie= ? ",(ucookie,))
    conn.commit()
    conn.close()
    response=make_response("退出登录成功")
    response.set_cookie('ucookie','',max_age=0)
    return "退出登录成功"

# 测试页面
# 项目最终不包含debug内容
if app.debug:
    @app.route('/test')
    @app.route('/testpage')
    @app.route('/debug')
    @app.route('/debugpage')
    def testpage():
        """
        debug特有页面
        用于测试
        最终删除
        """
        return render_template("testpage.html.j2",debug=app.debug)
    @app.route('/icons')
    def icons():
        """
        debug特有页面
        图标
        """
        return send_file("icons.html")

# @app.errorhandler(404)
# @app.route("/<path:invalid_path>")
# def notfound(invalid_path):
#     """
#     404页面路由
#     """
#     return render_template("404.html.j2"),404

if __name__=="__main__":
    app.run()