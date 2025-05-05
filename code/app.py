from flask import Flask,request,render_template,send_file,jsonify,url_for,Blueprint
from pathlib import Path
import random
import string
from module.TlsCnnModel import TlsCnnModel as myAI
import asyncio
import json


# 页面初始设置
app=Flask(__name__)
# app.debug=1
filedir=Path(__file__).parent
temporarydir=Path("D:\\pcap")

# 食用函数
# 随机字符串
def randstr(len):
    return ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(len))

# 后端验证文件函数
def checkfile(file):
    if len(file.filename)>=1 and file.filename[-1:]==".":
        return False
    if len(file.filename)>=7 and file.filename[-7:]=="::$data":
        return False
    return True

# 页面
# 初始界面
@app.route("/")
@app.route("/index")
@app.route("/index.html")
def index():
    return render_template("index.html.j2",debug=app.debug)

# 上传
@app.route("/upload")
@app.route("/upload.html")
def upload():
    return render_template("upload.html.j2",debug=app.debug)

# 展示
# 先准备一个AI
myai=myAI()
# 实际上应该每个线程一个
# 但是每个线程分配一个太慢了
@app.route("/show")
@app.route("/show.html")
def show():
    # 获取灵饰位置
    files=request.args.get("files")                                              # 获取访问位置
    dir=temporarydir/"temporary"/files                                           # 得到实际路径
    
    # 从零时位置检测是否已存在结果文件
    result_file=dir/"result.json"                                                # 结果文件
    if result_file.exists():
        with open(result_file,"r") as f:
            results=json.load(f)
    else:

    # 从灵石位置获取pcap文件
        files=dir.glob("*.pcap")                                                 # 通配符查找所有文件
        files=list(map(lambda x:str(x),files))                                   # 转文件名为 str

        # 运行AI
        loop=asyncio.new_event_loop()                                            # pyshark太傻了，没有loop就不跑了
        asyncio.set_event_loop(loop)
        results=myai.detect(files)
        loop.close()

        # 返回结果
        results=map(lambda result:"tormeek" if result!=0 else "normal",results)
        files=map(lambda file:str(Path(file).name),files)                        # 整理结果与文件名
        results=list(zip(files,results))
        with open(result_file,"w") as f:                                         # 导出结果到文件
            json.dump(results,f)
    return render_template("show.html.j2",results=results,debug=app.debug)

# 食用功能
# 向前端传输文件
@app.route("/download")
def download():
    filename=request.args.get("filename")
    return send_file("source"+filename)

# 前端上传pcap文件
@app.route("/uploadpcap",methods=["post"])
def uploadpcap():
    if 'files' not in request.files:
        return "未上传文件",400
    else :
        files=request.files.getlist("files")
        for file in files:
            if checkfile(file)==False:
                return "存在不合法文件",400
        # 存放零食文件
        temdir=temporarydir/"temporary"
        if not temdir.exists():
            temdir.mkdir()
        place=""
        savepath=None
        while savepath==None or savepath.exists():
            place=randstr(16) # 随机文件夹名
            savepath=temdir/place
        savepath.mkdir()
        for file in files:
            file.save(str(savepath/file.filename))
            file.close()
        redirect_url=url_for("show",files=place)
        return jsonify(
            success=True,
            redirect_url=redirect_url
        )

# 测试页面
# 项目最终不包含debug内容
if app.debug:
    @app.route('/test')
    @app.route('/testpage')
    @app.route('/debug')
    @app.route('/debugpage')
    def testpage():
        return render_template("testpage.html.j2")

# @app.errorhandler(404)
@app.route("/<path:invalid_path>")
def notfound(invalid_path):
    return render_template("404.html.j2"),404

if __name__=="__main__":
    app.run()