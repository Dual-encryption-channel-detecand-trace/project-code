$(()=>{
    getuserinfo(function(userinfo){
        console.log(userinfo)
        if(userinfo==null)
            alert("请先登录");
        let $tablebody=$("#history>tbody");
        $tablebody.empty();
        let history=userinfo.history
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
            // $row.click(function()
            // {
            //     let $this=$(this);
            //     window.location.href=`/show?fileplace=${history[i].fileplace}`;
            // });
            $tablebody.append($row);
        }
    });
});