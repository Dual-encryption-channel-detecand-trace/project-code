"use strict"

var result;

function showdetail(pcapid=0,linkid=0)
{
    let linkdetail=result[pcapid].pcapdetail[linkid].linkdetail;
    console.log(linkdetail);
    circlegraph(linkdetail.protoflow,{name:'proto',value:'bytes'},'各协议流量占比','protocals');
    let $showfeatuer=$('#showfeatuer');
    $showfeatuer.empty();
    let $head=$('<h5>部分特征展示</h5>');
    $showfeatuer.append($head);
    let $text=$(`<p>ClientHello 版本:${Math.round(linkdetail.feature[0])}</p>`);
    $showfeatuer.append($text);
    $text=$(`<p>密码套件数量:${Math.round(linkdetail.feature[1])}</p>`);
    $showfeatuer.append($text);
    $text=$(`<p>extension数量:${Math.round(linkdetail.feature[2])}</p>`);
    $showfeatuer.append($text);
    let textsr;
    if(linkdetail.feature[3]>0.9)
        textsr='是'
    else textsr='否'
    $text=$(`<p>是否使用了伪造的服务器:${textsr}</p>`);
    $showfeatuer.append($text);
}
function showlinks(pcapid=0)
{
    let $tablebody=$("#resultlinks>tbody");
    $tablebody.empty();
    let pcapdetail=result[pcapid].pcapdetail;
    for(let i=0;i<pcapdetail.length;i++)
    {
        let $row=$("<tr class='clicklink'></tr>");
        //逐个组建信息
        let $cell=$(`<td>${pcapdetail[i].srcip}</td>`);
        $row.append($cell);
        $cell=$(`<td>${pcapdetail[i].dstip}</td>`);
        $row.append($cell);
        let cnt=pcapdetail[i].countflow;
        if(cnt>1024*1024)
            $cell=$(`<td>${(1.0*cnt/1024/1024).toFixed(2)} MB</td>`);
        else if(cnt>1024)
            $cell=$(`<td>${(1.0*cnt/1024).toFixed(2)} KB</td>`);
        else
            $cell=$(`<td>${cnt} Byte</td>`);
        $row.append($cell);
        $cell=$(`<td>${pcapdetail[i].result}</td>`);
        $row.append($cell);
        // 监听点击
        $row.click(function()
        {
            let $this=$(this);
            showdetail(pcapid,$this.index());
        });
        $tablebody.append($row);
    }
    showdetail(pcapid);
}
function showpcaps()
{
    let $tablebody=$("#resultpcaps>tbody");
    $tablebody.empty();
    for(let i=0;i<result.length;i++)
    {
        let $row=$("<tr class='clickpcap'></tr>");
        // 逐个组建信息
        let $cell=$(`<td>${result[i].filename}</td>`);
        $row.append($cell);
        $cell=$(`<td>${result[i].countlink}</td>`);
        $row.append($cell);
        let cnt=result[i].countflow;
        if(cnt>1024*1024)
            $cell=$(`<td>${(1.0*cnt/1024/1024).toFixed(2)} MB</td>`);
        else if(cnt>1024)
            $cell=$(`<td>${(1.0*cnt/1024).toFixed(2)} KB</td>`);
        else
            $cell=$(`<td>${cnt} Byte</td>`);
        $row.append($cell);
        $cell=$(`<td>${result[i].result}</td>`);
        $row.append($cell);
        $row.click(function()
        {
            let $this=$(this);
            showlinks($this.index());
        });
        $tablebody.append($row);
    }
    showlinks();//展示第一个
}

//ajax技术获取信息

$(() => 
{
    const urlParams = new URLSearchParams(window.location.search);
    const fileplace = urlParams.get('fileplace');
    const runai=()=>
    {
        $.ajax(
            {   url: '/do/runai'
            ,   type: 'POST'
            ,   contentType: 'application/json'
            ,   data: JSON.stringify({fileplace:fileplace})
            });
    };
    runai();
    let delay=5000;
    const fetchData=() =>
    {
        $.ajax(
            {   url: "/do/getinfo"
            ,   type: "POST"
            ,   contentType: 'application/json'
            ,   data: JSON.stringify({fileplace:fileplace})
            ,   dataType: "json"
            ,   success: (response,textStatus,xhr) =>
                {
                    if(xhr.status==202)
                    {
                        delay*=1.5;
                        setTimeout(fetchData,delay);
                        return ;
                    }
                    else if(xhr.status==204)
                    {
                        runai();
                        fetchData();
                        return ;
                    }
                    result=response.result;
                    showpcaps();
                    // 获取信息成功
                }
            ,   error: (xhr) =>
                {
                    if(xhr.status==401)
                    {
                        alert("没有权限，请确认是否登录");
                    }
                    //失败尝试再次获取信息
                }
            });
    };

    
    //定时获取数据
    fetchData();
});
/*
result要求
result:
[   {   filename: "str"
        countlink: num(int)
        countflow: num(int)
        result: "str"
        pcapdetail:
        [   {   srcip: "str"
                dstip: "str"
                countflow: num(int)
                result: "str"
                detail:
                {
                    info
                }
            }
        
        ]
    }
]


*/