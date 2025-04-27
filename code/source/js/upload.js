"use strict"
// $(()=>{
//     alert($("#upload").attr("action"))
// })
function checkpcapfile(file)
{
    if(file.name=="")
        return false;
    return true;
}

$(()=>{
    // 提交表单
    $("#upload").on("submit",(e)=>{
        // 拦截
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
                $("body").text("上传成功！3秒后跳转");
                window.location.href=response.redirect_url;
            }
        ,   error: (xhr,status,error)=>{
            alert(xhr.responseText)
            //处理错误
        }
        });
    });
});