"use strict"

// 石用功能
// 检验pcap文件合法性
function checkpcapfile(file)
{
    if(file.name=="")
        return false;
    return true;
}

// 上传文件功能
$(()=>{
    $("#upload").on("submit",(e)=>{
        // 拦截提交事件
        e.preventDefault();
        let $this=$("#upload");

        // 从form的属性获取url method
        let url=$this.attr("action");
        // 前端验证文件
        let files=$("#uploadpcap")[0].files;
        for(let i=0;i<files.length;i++)
            if(checkpcapfile(files[i])==false)
            {
                // 存在不合法文件
                alert("存在不合法文件或没有文件上传");
                return ;
            }

        // 上传
        let data=new FormData();
        Array.from(files).forEach((file)=>{
            data.append("files",file);
        });
        $.ajax(
        {   url: url
        ,   type: "POST"
        ,   data: data
        ,   cache: false
        ,   processData: false
        ,   contentType: false
        ,   success: (response)=>{
                $("#uploadcard").text("上传成功！3秒后跳转");
                window.location.href=response.redirect_url;
            }
        ,   error: (xhr,status,error)=>{
                //处理错误
                alert(xhr.responseText)
            }
        });
    });
});