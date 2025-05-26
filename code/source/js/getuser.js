
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
            if(callback!==undefined)
                callback(userinfo);
        }
    ,   error: (xhr)=>
        {
            $('#aboutuser').html('<li id="aboutuser" class="dropdown nav-item"><a href="/login">登录</a></li>')
        }
    });
    return userinfo;
    // getcookie
    // if not found 
    // return 
    // else send cookie
    // if 过期
    // alert("登录信息过期")
    // else
    // 更改header
    // 设置userinfo
}
$(getuserinfo());