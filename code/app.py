from flask import Flask,request,render_template,send_file,jsonify,url_for
from pathlib import Path
import random
import string
from module.TlsCnnModel import TlsCnnModel as myAI
import asyncio
from threading import Thread
app=Flask(__name__)

def randstr(len):
    return ''.join(random.choice(string.ascii_letters+string.digits) for _ in range(len))

# 先准备一个AI
myai=myAI()
# 实际上应该每个线程一个

# 后端验证文件函数
def checkfile(file):
    return True

filedir=Path(__file__).parent
temporarydir=Path("D:\\pcap")

# 初始界面
@app.route("/")
@app.route("/index")
@app.route("/index.html")
def index():
    return render_template("index.html")

# 上传
@app.route("/upload")
@app.route("/upload.html")
def upload():
    return render_template("upload.html")

# 展示
@app.route("/show")
@app.route("/show.html")
def show():
    files=request.args.get("files")
    dir=temporarydir/"temporary"/files

    # 从灵石位置获取pcap文件
    files=dir.glob("*.pcap")
    files=list(map(lambda x:str(x),files))
    
    # 运行AI
    loop=asyncio.new_event_loop() # pyshark太傻了，没有loop就不跑了
    asyncio.set_event_loop(loop)
    results=myai.detect(files)
    loop.close()
    # await(myai.detect(files))
    # return "end"

    # 返回结果
    results=map(lambda result:"tormeek" if result!=0 else "normal",results)
    files=map(lambda file:str(Path(file).name),files)
    results=list(zip(files,results))
    return render_template("show.html.j2",results=results)


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



# @app.errorhandler(404)
@app.route("/<path:invalid_path>")
def notfound(invalid_path):
    return render_template("404.html"),404

if __name__=="__main__":
    # app.run()
    app.run(debug=True)