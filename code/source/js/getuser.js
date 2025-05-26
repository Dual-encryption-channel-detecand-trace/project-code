function getuserinfo(callback)
{
    let userinfo=null;
    $.ajax(
    {   url: "/do/userinfo"
    ,   type: "POST"
    ,   dataType: "json"
    ,   contentType: 'application/json'
    ,   data: null
    ,   success: (response)=>
        {
            userinfo=response.userinfo;
        }
    ,   error: (xhr)=>
        {
            $('#aboutuser').html('<li id="aboutuser" class="dropdown nav-item"><a href="/login">登录</a></li>')
            let $regi=$('<li class="dropdown nav-item"><a href="/register">注册</a></li>');
            $('#aboutuser').after($regi);
        }
    });
}
$(getuserinfo());