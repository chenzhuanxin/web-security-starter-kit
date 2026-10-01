# 网络安全入门套件

从「看懂这个行业怎么赚钱」到「在自己电脑上真打一遍」的完整路径整理。所有内容基于实机实测，
所有网址均逐一验证过可访问性。

**在线浏览**：https://chenzhuanxin.github.io/web-security-starter-kit/

## 内容

| 文件 | 内容 |
|---|---|
| [index.html](index.html) | 导航首页 |
| [platforms.html](platforms.html) | 漏洞赏金 / 众测平台清单（四类 18 个平台，含注册入口与实名材料） |
| [labs-list.txt](labs-list.txt) | 练习靶场总清单（38 个网址实测）＋ 找漏洞的方法论 |
| [lab-walkthrough.html](lab-walkthrough.html) | 7 关入门靶场的完整实操记录（真实请求留档 + 报告模板） |
| [lab-with-tools.html](lab-with-tools.html) | 用 ffuf + SecLists 打 OWASP Juice Shop 的实战记录 |
| [toolkit.html](toolkit.html) | 真实项目工具链与操作手册（Burp 上手、8 阶段流水线） |
| [vulnlab/server.js](vulnlab/server.js) | 配套 7 关靶场源码，Node 原生，零依赖 |

## 跑起配套靶场

```bash
cd vulnlab
node server.js
# 浏览器访问 http://localhost:3000
```

要求 Node.js 18+。服务只监听 127.0.0.1，外网访问不到。进度重置访问 `/reset`。

## 前置声明

本仓库整理的是公开的平台入口、靶场资源与通用安全测试方法论，**不包含任何针对特定真实目标的漏洞信息，
也不构成任何测试授权**。

所有练习请限定于靶场、或平台明确列出的授权范围内进行。未获授权扫描或测试真实系统，
属于非法侵入计算机信息系统；以漏洞索取财物属于敲诈勒索，不是漏洞赏金。

---

内容整理时间：2026-10-01
