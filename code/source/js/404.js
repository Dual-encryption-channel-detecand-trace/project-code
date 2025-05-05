"use strict"
let t=5;
let showtime404;

// 倒计时
$(()=>{
    showtime404=setInterval(()=>{
        t=t-1;
        if(t>0)
            $("#time404").text(`${t}`);
    },1000);
});

// 自动跳转
$(()=>{
    setTimeout(()=>{
        clearInterval(showtime404);
        window.location.href="/index";
    },5000);
});