$(()=>{
    let userinfo=null;
    $.ajax(
    {   url: "/do/gethistory"
    ,   type: "POST"
    ,   dataType: "json"
    ,   contentType: 'application/json'
    ,   data: null
    ,   success: (response)=>
        {
            let history=response.history;
            if(history==null)
                alert("请先登录");
            let $tablebody=$("#history>tbody");
            $tablebody.empty();
            for(let i=0;i<history.length;i++)
            {
                let $row=$("<tr class='clickhistory'></tr>");
                // 逐个组建信息
                let $cell=$(`<td>${history[i].updtime}</td>`);
                $row.append($cell);
                $cell=$(`<td>${history[i].fcount}</td>`);
                $row.append($cell);
                $cell=$(`<td><a href=/show?fileplace=${history[i].fileplace}>详细信息</a></td>`);
                $row.append($cell);
                $tablebody.append($row);
            }
        }
    ,   error: (xhr)=>
        {}
    });
    return userinfo;
});