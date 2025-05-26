/** 
 * 如果有toe-meek应该优先返回
 * 其余按大小排序
*/

/**
 * 规范
 * 折线图：
 *  data:
 *  {
 *      eps: number
 *      data:[时间顺序
 *      [某时间的统计结果
 *      {
 *          name: "str"
 *          value: number
 *      },...],...]
 *  
 *  }
 * 扇形图：
 *  data:
 *  [
 *      {
 *      name:"str"
 *      value:number
 *      }...]
 */
//数据处理
const hightlight="#f00";   //高亮颜色
const leastsize=0.005;     //扇形图最小大小
//扇形图
function data2circle(data,names)
{
    let showdata=[];
    let sum=0;
    for(let i=0;i<data.length;i++)
        sum+=data[i][names.value];
    let other=0;
    for(let i=0;i<data.length;i++)
    {
        if(data[i][names.value]/sum>leastsize)
        {
            showdata.push(
                {   value: data[i][names.value]
                ,   name: data[i][names.name]
                });
            if(data[i][names.name]=="tormeek")
            {
                showdata[showdata.length-1]=Object.assign(showdata[showdata.length-1],
                    {   itemStyle:
                        {   color: hightlight
                        }
                    });
            }
        }
        else
            other+=data[i][names.value];
    }
    if(other!=0)
    {
        showdata.push(
            {   value: sum-other
            ,   name: 'other'
            });
    }
    return showdata;
}

//折线图
function data2line(data,names)
{
    let eps=data.eps;
    data=data.data
    let showdata=[],showo=[];
    for(let t=0;t<data.length;t++)
    {
        for(let i=0;i<data[t].length;i++)
        {
            let found=false;
            for(let j=0;j<showdata.length;j++)
            {
                if(data[t][i].name==showdata[j].name)
                {
                    found=true;
                    showdata[j].data.push([(t+1*eps),data[t][i].value]);
                }
            }
            if(found==false)
            {
                showo.push([(t+1)*eps,data[t][i][names.value]]);
                showdata.push(
                    {   name: data[t][i][names.name]
                    ,   type: "line"
                    ,   data: JSON.parse(JSON.stringify(showo))
                    }
                )
                showo.pop();
                if(data[t][i].name=="tormeek")
                {
                    showdata[showdata.length-1]=Object.assign(showdata[showdata.length-1],
                        {   itemStyle:
                            {   color: hightlight
                            }
                        });
                }
            }
        }
        for(let j=0;j<showdata.length;j++)
            if(showdata[j].data.length==t)
                showdata[j].data.push([(t+1)*eps,0]);
        showo.push([(t+1)*eps,0]);
    }
    return showdata;
}

// 作图
//扇形图
function circlegraph(data,names,chartname,containerid)
{
    data=data2circle(data,names);
    // 作图
    const chartDom = $(`#${containerid}`)[0];
    const myChart = echarts.init(chartDom);

    const option=
    {   title:
        {   text: chartname
        ,   top: 'top'
        ,   left: 'center'
        ,   textStyle:
            {   color: 'white'
            }
        }
    ,   tooltip:
        {   trigger: 'item'
        }
    ,   legend:
        {   top: '10%'
        ,   textStyle:
            {   color: 'white'
            }
        }
    ,   series:
        [   {   type: 'pie'
            ,   radius:
                [   '40%'
                ,   '70%'
                ]
            ,   avoidLabelOverlap: false
            ,   label:
                {   show: false
                ,   position: 'center'
                }
            ,   emphasis:
                {   label:
                    {   show: false
                    }
                }
            ,   labelLine:
                {   show: false
                }
            ,   data: data
            }
        ]
    };

    option && myChart.setOption(option);
}

//折线图
function linegraph(data,names,chartname,containerid)
{
    data=data2line(data,names);

    const chartDom = $(`#${containerid}`)[0];
    const myChart = echarts.init(chartDom);

    const option =
    {   title:
        {   text: chartname
        ,   textStyle:
            {   color: 'white'
            }
        }
    ,   tooltip:
        {   trigger: 'axis'
        }
    ,   grid:
        {   left: '3%'
        ,   right: '4%'
        ,   bottom: '3%'
        ,   containLabel: true
        }
    ,   legend:
        {   top: '10%'
        ,   textStyle:
            {   color: '#fff'
            }
        }
    ,   toolbox:
        {   feature:
            {   saveAsImage: {}
            }
        }
    ,   xAxis: {}
    ,   yAxis: {}
    ,   series: data
    };
    option && myChart.setOption(option);
}