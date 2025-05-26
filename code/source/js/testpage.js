"use strict"

$(() =>
{
    $("#login").submit(function(e){
        e.preventDefault();
        let formData = $(this).serializeArray();
        console.log(formData);
    });
});