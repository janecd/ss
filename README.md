#### 说明
---
直接进入shadowsocks目录,运行local.py或者server.py即可


### 用法
----

1.

    在本地和VPS分别下载下来后，VPS上面拷贝config.json.sample.for_server并复制  
    一份放在和config.json.sample.for_server相同的路径下，重命名为config.json。  
    修改里面的{"port_password"}，修改成你自己的设置。然后运行server.py，开启服务。
2.

    在本地，拷贝config.json.sample.for_local并复制一份放在和config.json.sample.for_local  
    相同的路径下，重命名为config.json。  
    修改里面的{"server","port_password","server_port","server_info"}  
    ，但是注意哦，需要把{"port_password"}保持和VPS里面的信息一致。
3.

    好了，在本地运行local.py，修改浏览器的socket代理为127.0.0.1:1080，fuck GFW吧！


### 关于本项目
---

我会不断的优化和改进，当然了，也欢迎大家一起来改进。我自己的能力也有限。 ：）
