"use strict"

$(() =>
{
    $("#loginfm").submit(function(e)
    {
        e.preventDefault();
        let data=$(this).serializeArray(),rdata={};
        for(let i=0;i<data.length;i++)
            rdata[data[i].name]=data[i].value;
        data=rdata;
        $.ajax(
            {   url: "/do/login"
            ,   type: "POST"
            ,   dataType: "json"
            ,   contentType: 'application/json'
            ,   data: JSON.stringify(data)
            ,   success: () =>
                {
                    // Cookies.set("ucookie",ucookie,{expires:3,path:"/"});
                    alert("登录成功");
                    //获取信息成功
                    window.location.href='/index'
                }
            ,   error: (xhr) =>
                {
                    alert("登录失败");
                }
            }
        );
    });
});