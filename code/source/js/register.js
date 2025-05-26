"use strict"

$(() =>
{
    $("#regfm").submit(function(e)
    {
        e.preventDefault();
        let data=$(this).serializeArray(),rdata={};
        for(let i=0;i<data.length;i++)
            rdata[data[i].name]=data[i].value;
        data=rdata;
        if(data.passwd!=data.passwd2)
        {
            alert("密码不匹配");
            return ;
        }
        $.ajax(
            {   url: "/do/register"
            ,   type: "POST"
            ,   dataType: "json"
            ,   contentType: 'application/json'
            ,   data: JSON.stringify(data)
            ,   success: () =>
                {
                    alert("注册成功");
                    window.location.href="/login";
                }
            ,   error: (xhr) =>
                {
                    alert("注册失败");
                }
            }
        );
    });
});