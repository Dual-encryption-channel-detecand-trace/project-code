"use strict"

// 石用功能
// 检验pcap文件合法性
function checkpcapfile(file)
{
    if(file.name=="")
        return false;
    return true;
}

function randomString(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// 上传文件功能
$(()=>{
    $("#upload").on("submit",function(e){
        // 拦截提交事件
        e.preventDefault();
        let $this=$(this);

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
        const chunkSize = 10 * 1024 * 1024; // 10MB
        let fileplace=randomString();
        for (let i = 0; i < files.length; i++) {
            const file = files[i];
            let offset = 0;
            while (offset < file.size) {
                let data=new FormData();
                const chunk = file.slice(offset, offset + chunkSize);
                data.append('chunk', chunk);
                data.append('chunkInfo', JSON.stringify({
                    filename: file.name,
                    size: file.size,
                    fileplace: fileplace,
                    id: Math.floor(offset / chunkSize),
                    fid: i,
                    count: Math.floor((file.size-1) / chunkSize)+1,
                    fcount: files.length,
                }));
                offset += chunkSize;
                console.log(data)
                $.ajax(
                {   url: url
                ,   type: "POST"
                ,   data: data
                ,   dataType: "json"
                ,   cache: false
                ,   processData: false
                ,   contentType: false
                ,   success: (response)=>{}
                ,   error: (xhr,status,error)=>{
                        //处理错误
                        if(xhr.status==401)
                        {
                            window.href='/login';
                        }
                    }
                });
            }
        }
        let data=new FormData();
        Array.from(files).forEach((file)=>{
            data.append("files",file);
        });
    });
});