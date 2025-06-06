"use strict"

// 石用功能
// 检验pcap文件合法性
function checkpcapfile(file)
{
    if(file.name=="")
        return false;
    return true;
}

let count=[],fcount=0,nowcount=[],nowfcount=0;
function uploadchunk(files,offset,info,$tablex)
{
    const chunkSize=info.chunkSize;
    const fid=info.fid;
    const url=info.url;
    const fileplace=info.fileplace
    const file=files[fid];

    let data=new FormData();
    const chunk = file.slice(offset, offset + chunkSize);
    data.append('chunk', chunk);
    data.append('chunkInfo', JSON.stringify(
    {   filename: file.name
    ,   size: file.size
    ,   fileplace: fileplace
    ,   id: Math.floor(offset / chunkSize)
    ,   fid: fid
    ,   count: Math.floor((file.size-1) / chunkSize)+1
    ,   fcount: fcount
    }));
    $.ajax(
    {   url: url
    ,   type: "POST"
    ,   data: data
    ,   dataType: "json"
    ,   cache: false
    ,   processData: false
    ,   contentType: false
    ,   success: (response)=>{
            ++nowcount[fid];
            if(nowcount[fid]+1==count[fid])
            {
                console.log(info);
                uploadchunk(files,(count[fid]-1)*chunkSize,info,$tablex);
            }
            if(nowcount[fid]==count[fid])
            {
                let $tbody=$($tablex.children()[1]);
                let $row=$($tbody.children()[fid]);
                let $cell=$($row.children()[2]);
                $cell.text("完成");
                ++nowfcount;
                if(nowfcount==fcount)
                    window.location.href=`/show?fileplace=${fileplace}`;
                if(nowfcount+1==fcount)
                {
                    let info_=info;
                    info_.fid=fcount-1;
                    uploadpcap(files,info,$tablex);
                }
            }
            else
            {
                let $tbody=$($tablex.children()[1]);
                let $row=$($tbody.children()[fid]);
                let $cell=$($row.children()[2]);
                let $aim=$($cell.children()[0]);
                $aim.text(`${(nowcount[fid]*100/count[fid]).toFixed(1)}`)
            }
        }
    ,   error: (xhr,status,error)=>{
            //处理错误
            // alert(xhr.status);
            if(xhr.status==401)
            {
                window.href='/login';
            }
            else{
                uploadchunk(file,offset,info,$tablex);
            }
        }
    });
}
function uploadpcap(files,info,$tablex)
{
    const fid=info.fid;
    const file=files[fid];
    const chunkSize=info.chunkSize;
    let offset = 0;
    if(offset+chunkSize>=file.size)
    {
        uploadchunk(files,0,info,$tablex);
        return ;
    }
    while (offset+chunkSize < file.size) {
        uploadchunk(files,offset,info,$tablex);
        offset+=chunkSize;
    }
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
        const url=$this.attr("action");

        // 前端验证文件
        let files=$("#uploadpcap")[0].files;
        count=[],fcount=files.length,nowcount=[],nowfcount=0;
        for(let i=0;i<files.length;i++)
            if(checkpcapfile(files[i])==false)
            {
                // 存在不合法文件
                alert("存在不合法文件或没有文件上传");
                return ;
            }
        // 上传
        const chunkSize = 10 * 1024 * 1024; // 10MB
        let $f=$('#upload').parent();
        $f.empty();
        $f.append($('<div class="card-header"><h5 class="title">提交情况</h5></div>'));
        let $tablex=$('<table class="table tablesorter"></table>');
        $tablex.append($('<thead></thead>'));
        let $tbody=$('<tbody></tbody>')
        for(let i=0;i<files.length;i++)
        {
            let $row=$('<tr></tr>');
            let $cell;
            $cell=$(`<td>${files[i].name}</td>`);
            $row.append($cell);
            $cell=$('<td><span class="percent">0</span>%</td>');
            $row.append($cell);
            $row.prepend($('<td></td>'));
            count.push(Math.floor((files[i].size-1) / chunkSize)+1);
            nowcount.push(0);
            $tbody.append($row);
        }
        $tablex.append($tbody);
        $f.append($tablex);
        const fileplace=randomString();
        if(fcount==1)
        {
            uploadpcap(files,{chunkSize:chunkSize,fid:0,url:url,fileplace:fileplace},$tablex);
            return ;
        }
        for (let i = 0; i+1 < fcount; i++) {
            uploadpcap(files,{chunkSize:chunkSize,fid:i,url:url,fileplace:fileplace},$tablex);
        }
    });
});