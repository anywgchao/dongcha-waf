# coding:utf-8
from django.core.mail import EmailMultiAlternatives
from SeMF.settings import WEB_URL
from selenium import webdriver
import time, os
from email.header import Header

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from RBAC.models import User_mails

url = WEB_URL


def sendmails(name, email, password):
    try:
        mail_data = User_mails.objects.last()
        subject = '平台账号'
        usernames = mail_data.mails
        passwords = mail_data.mails_psd

        mail_msg = """
        <p>您的账号:{0}</p>
        <p>您的密码:{1}</p>
        <p><a href="{2}">项目地址</a></p>
        """.format(name, password, url)

        msg = MIMEText(mail_msg, 'html', 'utf-8')
        msg['Subject'] = subject  # 邮件的主题，也可以说是标题
        msg["From"] = "{0}<{1}>".format(mail_data.smtp_name, mail_data.mails)  # 发件人
        msg["To"] = '<{0}>'.format(email)  # 收件人

        server = smtplib.SMTP_SSL(mail_data.smtp_ip, 465)  # 发件人邮箱中的SMTP服务器，端口是25
        server.login(usernames, passwords)  # 括号中对应的是发件人邮箱账号、邮箱密码
        server.sendmail(mail_data.mails, [email, ], msg.as_string())  # 括号中对应的是发件人邮箱账号、收件人邮箱账号、发送邮件
        server.quit()
    except Exception as e:
        print(e)


def sendregistmail(email, argu):
    data = {'subject': 'SeMF账号初始化',
            'text_content': '',
            'html_content': ''}
    data['text_content'] = "您的SeMF安全管理平台账号初始化地址如下" + url + "/view/regist/" + argu + "  如无申请过该平台账号，请忽略该邮件"
    data['html_content'] = """
    <p>Dear user:</p>
    <p>    您的SeMF安全管控平台账号初始化地址已创建，<a href='""" + url + "/view/regist/" + argu + """'>点我</a>以完成账号初始化</p>
    <p>    如点击失效，请前往访问以下地址""" + url + "/view/regist/" + argu + """</p>
    <p>    如非本人操作，忽略该邮件</p>
    <p>    本邮件为安全管控平台SeMf系统邮件，请勿回复</p>
    """


def sendresetpsdmail(email, argu):
    data = {'subject': 'SeMF账号密码重置',
            'text_content': '',
            'html_content': ''}
    data['text_content'] = "您正在申请重置SeMF平台账号，请前往以下地址处理：" + url + "/view/resetpsd/" + argu + "  如无执行重置操作，请忽略该邮件"
    data['html_content'] = """
    <p>Dear user:</p>
    <p>    您正在申请重置SeMF的密码，请前往以下地址进行密码重置，<a href='""" + url + "/view/resetpsd/" + argu + """'>点我</a>以完成密码重置</p>
    <p>    如点击失效，请前往访问以下地址""" + url + "/view/resetpsd/" + argu + """</p>
    <p>    如非本人操作，忽略该邮件</p>
    <p>    本邮件为安全管控平台SeMf系统邮件，请勿回复</p>
    """


def send_waflog_mail(email, data):
    try:
        mail_data = User_mails.objects.last()
        sender = mail_data.mails
        receiver = email
        subject = 'WAF日志报表'
        username = mail_data.mails
        password = mail_data.mails_psd

        msg = MIMEMultipart('alternative')
        msg['Subject'] = Header(subject, 'utf-8')
        name = ''
        for k, v in data.items():
            name = k
            data = v
            html_content = '''
        <!DOCTYPE html>
        <html style="height: 100%">
           <head>
               <meta charset="utf-8">
               <link href="http://cdn.static.runoob.com/libs/bootstrap/3.3.7/css/bootstrap.min.css" rel="stylesheet">
                <style type="text/css">
                    .cardBox {width: 19%;
                        box-shadow: 0 4px 8px 0 rgba(0, 0, 0, 0.2), 0 6px 20px 0 rgba(0, 0, 0, 0.19);
                        text-align: center;float: left;margin-right: 10px;padding: 5px;padding-top: 15px;}
                    .headerBox {color: #fff;padding: 10px;font-size: 15px;height: 60px;}
                    .bodyBox {padding: 10px;}
                    .bodyBox p {margin-left: 5px;}
                </style>
           </head>
           <body style="height: 100%; margin: 0" onload="change();">
        <div style="height: 30%">
                    <div class="cardBox">
                        <div class="headerBox" style="background-color: #5BC0DE;">
                            <p>日拦截总数</p>
                        </div>
                        <div class="bodyBox">
                            <p>数量：
                                <a href="javascript:void(0)" class="label label-success" style="border-radius: .25em;">''' + \
                           data['counts'] + '''</a>
                            </p>
                            <p>较前日变化：<span style="color:green">''' + data['count_change'] + '''</span></p>
                        </div>
                    </div>

                    <div class="cardBox">
                        <div class="headerBox" style="background-color: #5BC0DE;">
                            <p>日风险拦截数</p>
                        </div>
                        <div class="bodyBox">
                            <p>数量：
                                <a href="javascript:void(0)" class="label label-success" style="border-radius: .25em;">''' + \
                           data['owasp_count'] + '''</a>
                            </p>
                            <p>较前日变化：<span style="color:green">''' + data['owasp_change'] + '''</span></p>
                        </div>
                    </div>

                    <div class="cardBox">
                        <div class="headerBox" style="background-color: #5BC0DE;">
                            <p>cc规则拦截数</p>
                        </div>
                        <div class="bodyBox">
                            <p>数量：
                                <a href="javascript:void(0)" class="label label-success" style="border-radius: .25em;">''' + \
                           data['cc_count'] + '''</a>
                            </p>
                            <p>较前日变化：<span style="color:green">''' + data['cc_change'] + '''</span></p>
                        </div>
                    </div>

                    <div class="cardBox">
                        <div class="headerBox" style="background-color: #5BC0DE;">
                            <p>非中国区拦截数</p>
                        </div>
                        <div class="bodyBox">
                            <p>数量：
                                <a href="javascript:void(0)" class="label label-success" style=yinggaimeinayemiandoycledoukyhuichele"border-radius: .25em;">''' + \
                           data['geo_count'] + '''</a>
                            </p>
                            <p>较前日变化：<span style="color:green">''' + data['geo_change'] + '''</span></p>
                        </div>
                    </div>

                    <div class="cardBox">
                        <div class="headerBox" style="background-color: #5BC0DE;">
                            <p>被攻击站点</p>
                        </div>
                        <div class="bodyBox">
                            <p>数量：
                                <a href="javascript:void(0)" class="label label-success" style="border-radius: .25em;">''' + \
                           data['attack_count'] + '''</a>
                            </p>
                            <p>较前日变化：<span style="color:green">''' + data['attack_change'] + '''</span></p>
                        </div>
                    </div>           
                </div>

               <div id="container" style="height: 400px;width: 600px;float:left"></div>
               <div id="containers" style="height: 400px;width: 700px;float:left"></div>
               <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/echarts/dist/echarts.min.js"></script>
             <script type="text/javascript">
            function change ()
            {
                var divs = document.getElementsByTagName ("span");
                for ( var i = 0; i < divs.length; i++)
                {
                    var obj = divs[i];
                    var num = parseFloat (obj.firstChild.nodeValue);
                    obj.style.color = num > 0 ? "red" : "green";
                }
            };
        </script>  
               <script type="text/javascript">
        var dom = document.getElementById("container");
        var myChart = echarts.init(dom);
        var app = {};
        option = null;
        option = {
            title : {
                text: 'web攻击类型',
                subtext: '',
                x:'center'
            },
            tooltip : {
                trigger: 'item',
                formatter: "{a} <br/>{b} : {c} ({d}%)"
            },
            legend: {
                orient: 'vertical',
                left: 'left',
                data: ''' + str(data['result1']['categories']) + '''
            },
            series : [
                {
                    name: '攻击来源',
                    type: 'pie',
                    radius : '55%',
                    center: ['50%', '60%'],
                    data:''' + str(data['result1']['data']) + ''',
                    itemStyle: {
                        emphasis: {
                            shadowBlur: 10,
                            shadowOffsetX: 0,
                            shadowColor: 'rgba(0, 0, 0, 0.5)'
                        }
                    }
                }
            ]
        };
        ;
        if (option && typeof option === "object") {
            myChart.setOption(option, true);
        }
               </script>

         <script type="text/javascript">
        var dom = document.getElementById("containers");
        var myChart = echarts.init(dom);
        var app = {};
        option = null;
        option = {
            title: {
                text: '攻击走势'
            },
            tooltip: {
                trigger: 'axis'
            },
            legend: {
                data:['XSS攻击','信息泄露','SQL注入','普通攻击','文件读取','其他']
            },
            grid: {
                left: '3%',
                right: '4%',
                bottom: '3%',
                containLabel: true
            },
            toolbox: {
                feature: {
                    saveAsImage: {}
                }
            },
            xAxis: {
                type: 'category',
                boundaryGap: false,
                data: ''' + str(data['result2']['date']) + '''
            },
            yAxis: {
                type: 'value'
            },
            series: [
                {
                    name:'XSS攻击',
                    type:'line',
                    smooth: true,
                    data:''' + str(data['result2']['xss_date']) + '''
                },
                {
                    name:'信息泄露',
                    type:'line',
                    smooth: true,
                    data:''' + str(data['result2']['info_date']) + '''
                },
                {
                    name:'SQL注入',
                    type:'line',
                    smooth: true,
                    data:''' + str(data['result2']['sql_date']) + '''
                },
                {
                    name:'普通攻击',
                    type:'line',
                    smooth: true,
                    data:''' + str(data['result2']['common_date']) + '''
                },
                {
                    name:'命令注入',
                    type:'line',
                    smooth: true,
                    data:''' + str(data['result2']['file_date']) + '''
                },
                {
                    name:'文件读取',
                    type:'line',
                    smooth: true,
                    data:''' + str(data['result2']['command_date']) + '''
                },
                {
                    name:'其他',
                    type:'line',
                    smooth: true,
                    data:''' + str(data['result2']['other_date']) + '''
                }
            ]
        };
        ;
        if (option && typeof option === "object") {
            myChart.setOption(option, true);
        }
               </script>

           </body>
        </html>
        '''
            try:
                os.remove('./static/waf_log-' + k + '.html')
                os.remove('./static/waf_log-' + k + '.jpg')
            except:
                pass
            with open('./static/waf_log-' + k + '.html', 'a') as f:
                f.write(html_content)
            driver = webdriver.PhantomJS()
            driver.get("./static/waf_log-" + k + ".html")
            time.sleep(4)
            driver.maximize_window()
            driver.save_screenshot("./static/waf_log-" + k + ".jpg")
            driver.close()

        html = '''
                    <!DOCTYPE HTML>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>waf日志分析</title>
        </head>
        <body>
        <img src="{0}/static/waf_log-{1}.jpg" height=100% width=100%/></p>
        </body>
        </html>
            '''.format(url, name)
        htm = MIMEText(html, 'html', 'utf-8')
        msg.attach(htm)

        # 构造图片

        fp = open('./static/waf_log-{0}.jpg'.format(name), 'rb')
        msgImage = MIMEImage(fp.read())
        fp.close()

        msgImage.add_header('Content-ID', '<image1>')
        msg.attach(msgImage)
        msg["From"] = "{0}<{1}>".format(mail_data.smtp_name, mail_data.mails)  # 发件人
        msg["To"] = '<{0}>'.format(email)  # 收件人

        # 构造附件

        att = MIMEText(open('./static/waf_log-{0}.html'.format(name), 'rb').read(), 'base64', 'utf-8')
        att["Content-Type"] = 'application/octet-stream'
        att["Content-Disposition"] = 'attatchment;filename="waf_log-{0}.html"'.format(name)
        msg.attach(att)

        smtp = smtplib.SMTP()
        smtp.connect(mail_data.smtp_ip)
        smtp.login(username, password)
        smtp.sendmail(sender, receiver, msg.as_string())
        smtp.quit()
    except Exception as e:
        print(e)
